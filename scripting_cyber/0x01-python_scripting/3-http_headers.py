#!/usr/bin/env python3

import requests

def get_http_headers(url):
    """
    Retrieves HTTP response headers from a website.
    
    Args:
        url (str): The URL to fetch headers from
        
    Returns:
        dict or None: A dictionary containing 'status_code' and 'headers' 
                      if successful, None if the request fails.
                      Format: {'status_code': int, 'headers': dict}
    """
    try:
        response = requests.get(url)
        
        # Convert response headers to a standard dictionary
        headers_dict = dict(response.headers)
        
        return {
            'status_code': response.status_code,
            'headers': headers_dict
        }
        
    except requests.exceptions.RequestException:
        # Catch all requests-related exceptions
        return None
