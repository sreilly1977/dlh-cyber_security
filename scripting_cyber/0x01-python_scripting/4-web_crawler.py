#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def crawl_website(start_url, max_depth=2):
    """
    Crawl a website recursively up to a specified depth.

    Args:
        start_url (str): The starting URL to crawl
        max_depth (int): Maximum depth to crawl (default: 2)

    Returns:
        set: A set of all successfully visited URLs within the same domain
    """
    visited = set()

    # Validate the starting URL
    try:
        parsed_start = urlparse(start_url)
        if not parsed_start.scheme or not parsed_start.netloc:
            return visited
        base_domain = parsed_start.netloc
    except Exception:
        return visited

    def _crawl(url, current_depth):
        # Base case: if we've exceeded max depth or already visited this URL
        if current_depth > max_depth or url in visited:
            return

        try:
            # Fetch the page
            response = requests.get(
                url,
                timeout=10,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; LumoCrawler/1.0)'}
            )

            # Check if request was successful
            if response.status_code != 200:
                return

            # Parse HTML content
            soup = BeautifulSoup(response.text, 'html.parser')

            # Add current URL to visited set
            visited.add(url)

            # Find all anchor tags with href attributes
            links = soup.find_all('a', href=True)

            for link in links:
                href = link['href']

                # Convert relative URLs to absolute URLs
                absolute_url = urljoin(url, href)

                # Parse the absolute URL
                try:
                    parsed_link = urlparse(absolute_url)

                    # Only crawl same domain URLs
                    if parsed_link.netloc == base_domain:
                        # Normalize URL (remove fragments, etc.)
                        normalized_url = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                        if parsed_link.query:
                            normalized_url += f"?{parsed_link.query}"

                        # Recursively crawl
                        _crawl(normalized_url, current_depth + 1)

                except Exception:
                    # Skip invalid URLs
                    continue

        except requests.exceptions.ConnectionError:
            # Handle connection errors
            pass
        except requests.exceptions.Timeout:
            # Handle timeout errors
            pass
        except requests.exceptions.RequestException:
            # Handle other request-related errors
            pass
        except Exception:
            # Handle any other unexpected errors
            pass

    # Start the crawling process
    _crawl(start_url, 0)

    return visited
