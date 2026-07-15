#!/bin/bash
for type in A AAAA MX NS TXT CNAME SOA SRV PTR SPF DKIM; 
        do echo "=== $type ==="; 
        dig $1 $type +short; 
done
