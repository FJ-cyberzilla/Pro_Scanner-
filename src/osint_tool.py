#!/usr/bin/env python3
"""
Pro_Scanner - Advanced OSINT Tool with perfect type safety.
Fully compliant with MyPy strict mode.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from typing import Any, Dict, List, Optional, cast

import aiosqlite
import httpx
from bs4 import BeautifulSoup


class Colors:
    """ANSI color codes for terminal output."""
    
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


class DatabaseManager:
    """Manages SQLite database operations with perfect type safety."""
    
    def __init__(self, db_path: str = "scan_data.db") -> None:
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
    async def init_db(self) -> None:
        """Initialize database tables if they don't exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "CREATE TABLE IF NOT EXISTS results ("
                "username TEXT, site_name TEXT, url TEXT, status TEXT, "
                "http_code INTEGER, response_time REAL, timestamp REAL, "
                "PRIMARY KEY (username, site_name))"
            )
            await db.commit()

    async def get_cached_result(self, username: str, site_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if not expired.
        
        Args:
            username: Target username
            site_name: Platform name
            
        Returns:
            Cached result dict or None if not found/expired
        """
        cutoff: float = time.time() - (24 * 3600)
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT url, status, http_code, response_time FROM results "
                "WHERE username = ? AND site_name = ? AND timestamp > ?",
                (username, site_name, cutoff),
            )
            row = await cursor.fetchone()
            return (
                {
                    "siteName": site_name,
                    "url": str(row[0]),
                    "status": str(row[1]),
                    "httpCode": int(row[2]),
                    "responseTime": float(row[3]),
                }
                if row
                else None
            )

    async def save_result(self, username: str, result: Dict[str, Any]) -> None:
        """Save scan result to database.
        
        Args:
            username: Target username
            result: Scan result dictionary
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    username,
                    str(result["siteName"]),
                    str(result["url"]),
                    str(result["status"]),
                    int(result.get("httpCode", 0)),
                    float(result.get("responseTime", 0.0)),
                    time.time(),
                ),
            )
            await db.commit()


def is_username_found(response: httpx.Response) -> bool:
    """Determine if username exists based on HTTP response.
    
    Args:
        response: HTTPX response object
        
    Returns:
        Boolean indicating if username was found
    """
    if response.status_code != 200:
        return False

    html_content: str = response.text.lower()
    soup: BeautifulSoup = BeautifulSoup(response.text, "html.parser")

    error_indicators: List[str] = [
        "not found",
        "does not exist",
        "404",
        "no such user",
        "user not found",
        "profile not found",
        "doesn't exist",
    ]

    if any(error in html_content for error in error_indicators):
        return False

    success_indicators: List[str] = [
        "profile",
        "member",
        "user",
        "account",
        "posts",
        "followers",
        "following",
        "tweets",
        "repositories",
    ]

    if any(success in html_content for success in success_indicators):
        return True

    if soup.title:
        title_text: str = soup.title.get_text().lower()
        if "profile" in title_text or "user" in title_text:
            return True

    return False


async def scan_site(username: str, site_name: str, site_data: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a single site for username existence.
    
    Args:
        username: Target username to scan
        site_name: Name of the platform
        site_data: Platform configuration data
        
    Returns:
        Dictionary with scan results
    """
    url_template: Optional[Any] = site_data.get("url")
    if not url_template or not isinstance(url_template, str):
        return {
            "siteName": site_name,
            "url": "N/A",
            "status": "ERROR",
            "httpCode": 0,
            "responseTime": 0.0,
        }

    full_url: str = url_template.format(username)
    start_time: float = time.time()

    headers: Dict[str, str] = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    try:
        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, limits=httpx.Limits(max_connections=10)
        ) as client:
            response: httpx.Response = await client.get(full_url, headers=headers)
            response_time: float = round(time.time() - start_time, 2)

            is_found: bool = is_username_found(response)
            status: str = "FOUND" if is_found else "NOT FOUND"

            return {
                "siteName": site_name,
                "url": str(response.url),
                "status": status,
                "httpCode": response.status_code,
                "responseTime": response_time,
            }

    except httpx.TimeoutException:
        return {
            "siteName": site_name,
            "url": full_url,
            "status": "TIMEOUT",
            "httpCode": 0,
            "responseTime": round(time.time() - start_time, 2),
        }
    except httpx.RequestError:
        return {
            "siteName": site_name,
            "url": full_url,
            "status": "ERROR",
            "httpCode": 0,
            "responseTime": round(time.time() - start_time, 2),
        }


def load_sites_config() -> Dict[str, Any]:
    """Load sites configuration from JSON file with perfect type safety.
    
    Returns:
        Dictionary of platform configurations
    """
    sites_file: str = "sites.json"
    default_sites: Dict[str, Any] = {
        "GitHub": {"url": "https://github.com/{}"},
        "Twitter": {"url": "https://twitter.com/{}"},
        "Instagram": {"url": "https://instagram.com/{}"},
        "Reddit": {"url": "https://reddit.com/user/{}"},
        "YouTube": {"url": "https://youtube.com/@{}"},
    }

    if not os.path.exists(sites_file):
        with open(sites_file, "w", encoding="utf-8") as file:
            json.dump(default_sites, file, indent=2)
        print(f"{Colors.YELLOW}Created default {sites_file}{Colors.RESET}")
        return default_sites

    try:
        with open(sites_file, "r", encoding="utf-8") as file:
            loaded_data: Any = json.load(file)
            # Use cast to ensure type safety with MyPy strict mode
            return cast(Dict[str, Any], loaded_data)
    except (json.JSONDecodeError, FileNotFoundError) as error:
        print(f"{Colors.RED}Error loading {sites_file}: {error}{Colors.RESET}")
        return default_sites


async def run_scan(username: str, sites_config: Dict[str, Any]) -> None:
    """Main scanning function orchestrating the scan process.
    
    Args:
        username: Target username to scan
        sites_config: Dictionary of platform configurations
    """
    db: DatabaseManager = DatabaseManager()
    await db.init_db()

    cached_results: List[Dict[str, Any]] = []
    sites_to_scan: List[tuple[str, Dict[str, Any]]] = []

    for site_name in sites_config.keys():
        cached_data = await db.get_cached_result(username, site_name)
        if cached_data:
            cached_results.append(cached_data)
        else:
            sites_to_scan.append((site_name, sites_config[site_name]))

    if cached_results:
        print(f"\n{Colors.CYAN}📦 Cached Results:{Colors.RESET}")
        for result in cached_results:
            status_color: str = Colors.GREEN if result["status"] == "FOUND" else Colors.YELLOW
            print(f"  {status_color}●{Colors.RESET} {result['siteName']}: {result['status']}")

    if sites_to_scan:
        print(f"\n{Colors.CYAN}🔍 Live Scanning {len(sites_to_scan)} sites:{Colors.RESET}")
        
        tasks: List[Any] = [
            scan_site(username, site_name, site_data) for site_name, site_data in sites_to_scan
        ]
        results: List[Dict[str, Any]] = await asyncio.gather(*tasks)

        found_count: int = 0
        for result in results:
            await db.save_result(username, result)

            status_color: str = Colors.GREEN if result["status"] == "FOUND" else Colors.YELLOW
            if result["status"] == "ERROR":
                status_color = Colors.RED

            status_icon: str = "✅" if result["status"] == "FOUND" else "❌"
            if result["status"] == "FOUND":
                found_count += 1

            print(
                f"  {status_color}{status_icon} {result['siteName']}: {result['status']} "
                f"({result['responseTime']}s){Colors.RESET}"
            )

    total_found: int = sum(1 for r in cached_results if r["status"] == "FOUND") + found_count
    total_sites: int = len(cached_results) + len(sites_to_scan)

    print(f"\n{Colors.GREEN}🎉 Scan complete!{Colors.RESET}")
    print(f"   Found {total_found} profiles out of {total_sites} sites")
    print(f"   Username: {Colors.BOLD}{username}{Colors.RESET}")


def main() -> None:
    """Main entry point for the OSINT tool."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="OSINT Username Scanner")
    parser.add_argument("username", nargs="?", help="Username to scan")
    parser.add_argument("--platforms", help="Comma-separated platforms to check")
    parser.add_argument("--export", choices=["json", "txt"], help="Export format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args: argparse.Namespace = parser.parse_args()
    sites_config: Dict[str, Any] = load_sites_config()

    username: str = args.username or input(f"{Colors.YELLOW}Enter username to scan: {Colors.RESET}").strip()
    if not username:
        print(f"{Colors.RED}No username provided{Colors.RESET}")
        return

    print(f"{Colors.BLUE}Starting scan for '{username}'...{Colors.RESET}")
    asyncio.run(run_scan(username, sites_config))


if __name__ == "__main__":
    main()
