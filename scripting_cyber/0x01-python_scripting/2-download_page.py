#!/usr/bin/env python3

import requests
from bs4 import BeautifulSoup

def download_page(url):
    """
    Downloads a web page and returns its formatted HTML content.
    
    Args:
        url: The URL of the web page to download
        
    Returns:
        str: Formatted HTML content if successful, error message if failed
    """
    try:
        # Fetch the web page
        response = requests.get(url, timeout=10)
        
        # Raise an exception for HTTP errors
        response.raise_for_status()
        
        # Parse and format the HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        formatted_html = soup.prettify()
        
        return formatted_html
        
    except requests.exceptions.RequestException as e:
        return f"Download failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"
