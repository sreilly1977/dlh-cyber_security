#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set

def crawl_website(start_url: str, max_depth: int = 2) -> Set[str]:
    """
    Recursively crawl a website starting from start_url up to max_depth levels.
    
    Args:
        start_url: The initial URL to start crawling from
        max_depth: Maximum depth to crawl (default: 2)
        
    Returns:
        A set of all successfully visited URLs within the same domain
    """
    visited = set()
    
    # Validate and normalize the starting URL
    try:
        parsed_start = urlparse(start_url)
        if not parsed_start.scheme or not parsed_start.netloc:
            return visited
        base_domain = parsed_start.netloc
    except Exception:
        return visited
    
    def _crawl(url: str, current_depth: int) -> None:
        # Base case: if we've reached max depth or already visited this URL
        if current_depth > max_depth or url in visited:
            return
        
        try:
            # Fetch the page
            response = requests.get(
                url, 
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; WebCrawler/1.0)'}
            )
            response.raise_for_status()
            
            # Add to visited set
            visited.add(url)
            
            # Parse HTML and extract links
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            # Process each link
            for link in links:
                href = link['href']
                absolute_url = urljoin(url, href)
                
                # Parse the absolute URL
                try:
                    parsed_link = urlparse(absolute_url)
                    
                    # Only crawl same domain
                    if parsed_link.netloc == base_domain:
                        # Normalize URL
                        normalized_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                        if parsed_link.query:
                            normalized_url += f"?{parsed_link.query}"
                        
                        # Recurse with increased depth
                        _crawl(normalized_url, current_depth + 1)
                        
                except Exception:
                    # Skip invalid URLs
                    continue
                    
        except (requests.exceptions.ConnectionError, 
                requests.exceptions.Timeout,
                requests.exceptions.RequestException,
                ValueError):
            # Skip unreachable URLs
            return
    
    # Start the recursive crawling
    _crawl(start_url, 0)
