#!/usr/bin/env python3

import socket

def resolve_domain_to_ipv4(domain_name):
    """
    Resolves a domain name to its IPv4 address.

    Args:
        domain_name (str): The domain name to resolve.

    Returns:
        str: The IPv4 address if successful.
        None: If the domain cannot be resolved.
        str: An error message string for any other exceptions.
    """
    try:
        # socket.gethostbyname() queries DNS for the A record
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    
    except socket.gaierror:
        # Raised when the domain cannot be resolved
        return None
    
    except Exception as e:
        # Catch-all for any other unexpected exceptions
        return f"An unexpected error occurred: {str(e)}"
