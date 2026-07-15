#!/usr/bin/env python3

import socket

def check_port(host, port, timeout=2):
    """
    Check if a specific port is open on a host.
    
    Args:
        host (str): IP address or hostname to check
        port (int): Port number to check (1-65535)
        timeout (int): Connection timeout in seconds
    
    Returns:
        bool: True if port is open, False if closed/unreachable
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set timeout for the connection attempt
        sock.settimeout(timeout)
        
        # Attempt connection using connect_ex (returns 0 on success)
        result = sock.connect_ex((host, port))
        
        # Close the socket
        sock.close()
        
        # Return True if connection succeeded (result == 0)
        return result == 0
        
    except socket.timeout:
        # Connection timed out
        return False
    except socket.error:
        # Socket error (invalid host, network issue, etc.)
        return False
    except Exception:
        # Catch-all for any other unexpected exceptions
        return False
