#!/bin/bash
if !$("postconf | grep -i smtp_tls_security_level = may"); echo "STARTTLS not configured"
