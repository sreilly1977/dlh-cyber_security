#!/usr/bin/env python3

import dns.resolver
from typing import Dict, Any

def query_dns_records(domain_name: str) -> Dict[str, Any]:
    """
    Query multiple DNS record types for a given domain.
    
    Args:
        domain_name: The domain to query (e.g., 'example.com')
        
    Returns:
        Dictionary containing DNS resolver answers organized by record type.
        Only includes record types that were successfully queried.
        Empty dictionary if domain cannot be resolved.
    """
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    results = {}
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            results[record_type] = answers
        except dns.resolver.NoAnswer:
            # Record type exists but no data for this domain
            continue
        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist - stop all queries
            return {}
        except dns.resolver.NoNameservers:
            # No nameservers available for this record type
            continue
        except Exception as e:
            # Handle any other unexpected errors
            print(f"Unexpected error querying {record_type}: {e}")
            continue
    
    return results
