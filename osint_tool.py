#!/usr/bin/env python3
"""
Pro_Scanner - Advanced OSINT Tool with async scanning capabilities.
Main module for username reconnaissance across multiple platforms.
"""

import argparse
import asyncio
import json
import os
import random
import sqlite3
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiosqlite
import httpx
from bs4 import BeautifulSoup


class Colors:
    """ANSI color codes for terminal output."""
    
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class DatabaseManager:
    """Manages SQLite database operations for caching scan results."""
    
    def __init__(self, db_path: str = "scan_data.db") -> None:
        """Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
    async def init_db(self) -> None:
        """Initialize database tables if they don't exist."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    username TEXT,
                    site_name TEXT,
                    url TEXT,
                    status TEXT,
                    http_code INTEGER,
                    response_time REAL,
                    timestamp REAL,
                    PRIMARY KEY (username, site_name)
                )
            """)
            await db.commit()

    async def get_cached_result(self, username: str, site_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached result if not expired (24 hours).
        
        Args:
            username: Target username
            site_name: Platform name
            
        Returns:
            Cached result dict or None if not found/expired
        """
        cutoff = time.time() - (24 * 3600)
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "SELECT url, status, http_code, response_time FROM results "
                "WHERE username=? AND site_name=? AND timestamp > ?",
                (username, site_name, cutoff)
            )
            row = await cursor.fetchone()
            if row:
                return {
                    "siteName": site_name,
                    "url": row[0],
                    "status": row[1],
                    "httpCode": row[2],
                    "responseTime": row[3]
                }
        return None

    async def save_result(self, username: str, result: Dict[str, Any]) -> None:
        """Save scan result to database.
        
        Args:
            username: Target username
            result: Scan result dictionary
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?, ?)",
                (username, result['siteName'], result['url'], result['status'], 
                 result['httpCode'], result['responseTime'], time.time())
            )
            await db.commit()


def is_username_found(response: httpx.Response, site_data: Dict[str, Any]) -> bool:
    """Determine if username exists based on HTTP response and content analysis.
    
    Args:
        response: HTTPX response object
        site_data: Platform configuration data
        
    Returns:
        Boolean indicating if username was found
    """
    if response.status_code != 200:
        return False

    html_content = response.text.lower()
    soup = BeautifulSoup(response.text, 'html.parser')

    # Check for explicit error messages
    error_indicators = [
        'not found', 'does not exist', '404', 'no such user', 
        'user not found', 'profile not found', 'doesn\'t exist'
    ]
    
    if any(error in html_content for error in error_indicators):
        return False

    # Check for success indicators
    success_indicators = [
        'profile', 'member', 'user', 'account', 'posts', 
        'followers', 'following', 'tweets', 'repositories'
    ]
    
    if any(success in html_content for success in success_indicators):
        return True

    # Check if username appears in title or page content
    if soup.title:
        title_text = soup.title.get_text().lower()
        if 'profile' in title_text or 'user' in title_text:
            return True

    # Default: if we get a 200 and no clear error, assume it exists
    return True


async def scan_site(username: str, site_name: str, site_data: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a single site for username existence.
    
    Args:
        username: Target username to scan
        site_name: Name of the platform
        site_data: Platform configuration data
        
    Returns:
        Dictionary with scan results
    """
    url_template = site_data.get("url")
    if not url_template:
        return {
            "siteName": site_name,
            "url": "N/A",
            "status": "ERROR",
            "httpCode": 0,
            "responseTime": 0
        }

    full_url = url_template.format(username)
    start_time = time.time()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }

    try:
        async with httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10)
        ) as client:
            
            response = await client.get(full_url, headers=headers)
            response_time = round(time.time() - start_time, 2)
            
            is_found = is_username_found(response, site_data)
            status = "FOUND" if is_found else "NOT FOUND"
            
            return {
                "siteName": site_name,
                "url": str(response.url),
                "status": status,
                "httpCode": response.status_code,
                "responseTime": response_time
            }

    except httpx.TimeoutException:
        return {
            "siteName": site_name,
            "url": full_url,
            "status": "TIMEOUT",
            "httpCode": 0,
            "responseTime": round(time.time() - start_time, 2)
        }
    except httpx.RequestError:
        return {
            "siteName": site_name,
            "url": full_url,
            "status": "ERROR",
            "httpCode": 0,
            "responseTime": round(time.time() - start_time, 2)
        }


async def run_scan(username: str, sites_config: Dict[str, Any]) -> None:
    """Main scanning function orchestrating the scan process.
    
    Args:
        username: Target username to scan
        sites_config: Dictionary of platform configurations
    """
    db = DatabaseManager()
    await db.init_db()

    # Check cache first
    cached_results = []
    sites_to_scan = []
    
    for site_name in sites_config.keys():
        cached_data = await db.get_cached_result(username, site_name)
        if cached_data:
            cached_results.append(cached_data)
        else:
            sites_to_scan.append((site_name, sites_config[site_name]))

    # Show cached results
    if cached_results:
        print(f"\n{Colors.CYAN}📦 Cached Results:{Colors.RESET}")
        for result in cached_results:
            status_color = Colors.GREEN if result['status'] == 'FOUND' else Colors.YELLOW
            print(f"  {status_color}●{Colors.RESET} {result['siteName']}: {result['status']}")

    # Scan new sites
    if sites_to_scan:
        print(f"\n{Colors.CYAN}🔍 Live Scanning {len(sites_to_scan)} sites:{Colors.RESET}")
        
        tasks = []
        for site_name, site_data in sites_to_scan:
            tasks.append(scan_site(username, site_name, site_data))
        
        results = await asyncio.gather(*tasks)
        
        found_count = 0
        for result in results:
            await db.save_result(username, result)
            
            status_color = Colors.GREEN if result['status'] == 'FOUND' else Colors.YELLOW
            if result['status'] == 'ERROR':
                status_color = Colors.RED
            
            status_icon = "✅" if result['status'] == 'FOUND' else "❌"
            if result['status'] == 'FOUND':
                found_count += 1
            
            print(f"  {status_color}{status_icon} {result['siteName']}: {result['status']} "
                  f"({result['responseTime']}s){Colors.RESET}")

    # Summary
    total_found = sum(1 for r in cached_results if r['status'] == 'FOUND') + found_count
    total_sites = len(cached_results) + len(sites_to_scan)
    
    print(f"\n{Colors.GREEN}🎉 Scan complete!{Colors.RESET}")
    print(f"   Found {total_found} profiles out of {total_sites} sites")
    print(f"   Username: {Colors.BOLD}{username}{Colors.RESET}")


def load_sites_config() -> Dict[str, Any]:
    """Load sites configuration from JSON file.
    
    Returns:
        Dictionary of platform configurations
    """
    sites_file = "sites.json"
    default_sites = {
        "GitHub": {"url": "https://github.com/{}"},
        "Twitter": {"url": "https://twitter.com/{}"},
        "Instagram": {"url": "https://instagram.com/{}"},
        "Reddit": {"url": "https://reddit.com/user/{}"},
        "YouTube": {"url": "https://youtube.com/@{}"}
    }
    
    if not os.path.exists(sites_file):
        with open(sites_file, 'w', encoding='utf-8') as file:
            json.dump(default_sites, file, indent=2)
        print(f"{Colors.YELLOW}Created default {sites_file}{Colors.RESET}")
        return default_sites

    try:
        with open(sites_file, 'r', encoding='utf-8') as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError) as error:
        print(f"{Colors.RED}Error loading {sites_file}: {error}{Colors.RESET}")
        return default_sites


def main() -> None:
    """Main entry point for the OSINT tool."""
    parser = argparse.ArgumentParser(description="OSINT Username Scanner")
    parser.add_argument("username", nargs="?", help="Username to scan")
    parser.add_argument("--platforms", help="Comma-separated platforms to check")
    parser.add_argument("--export", choices=["json", "txt"], help="Export format")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    sites_config = load_sites_config()
    
    if args.username:
        username = args.username
    else:
        username = input(f"{Colors.YELLOW}Enter username to scan: {Colors.RESET}").strip()
    
    if not username:
        print(f"{Colors.RED}No username provided{Colors.RESET}")
        return

    print(f"{Colors.BLUE}Starting scan for '{username}'...{Colors.RESET}")
    asyncio.run(run_scan(username, sites_config))


if __name__ == "__main__":
    main()
