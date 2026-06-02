#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import Set

def crawl_website(start_url, max_depth=2) -> Set[str]:
    """
    Recursively crawl a website starting from a given URL.
    
    Args:
        start_url: The starting URL to crawl from
        max_depth: Maximum depth to crawl (default: 2)
    
    Returns:
        A set of URLs that were successfully visited from the same domain
    
    Raises:
        None - exceptions are handled internally
    """
    visited = set()
    
    # Validate and normalize the start URL
    try:
        parsed_start = urlparse(start_url)
        if not parsed_start.scheme or not parsed_start.netloc:
            return visited
        base_domain = parsed_start.netloc
    except Exception:
        return visited
    
    def _crawl(url: str, current_depth: int) -> None:
        """Recursive helper function to crawl pages."""
        
        # Check if already visited or at max depth
        if url in visited or current_depth > max_depth:
            return
        
        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return
        except Exception:
            return
        
        # Only crawl same domain
        if parsed.netloc != base_domain:
            return
        
        # Mark as visited
        visited.add(url)
        
        # Try to fetch the page
        try:
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; LumoCrawler/1.0)'}
            )
            response.raise_for_status()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.RequestException,
                Exception):
            # Remove from visited if fetch failed
            visited.discard(url)
            return
        
        # Parse HTML and extract links
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all anchor tags with href attributes
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                
                # Convert relative URLs to absolute URLs
                absolute_url = urljoin(url, href)
                
                # Normalize URL (remove fragments, etc.)
                parsed_link = urlparse(absolute_url)
                normalized_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                if parsed_link.query:
                    normalized_url += f"?{parsed_link.query}"
                
                # Recursively crawl if not visited and within depth limit
                if normalized_url not in visited:
                    _crawl(normalized_url, current_depth + 1)
                    
        except Exception:
            # Failed to parse, continue anyway
            pass
    
    # Start the crawling process
    _crawl(start_url, 1)
    
    return visited
