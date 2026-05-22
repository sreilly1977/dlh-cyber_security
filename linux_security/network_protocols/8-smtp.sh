#!/bin/bash
if !$("postconf | grep -i smtpd_tls_security_level = may"); echo "STARTTLS not configured"
