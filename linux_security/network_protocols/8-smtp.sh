#!/bin/bash
if ! postconf smtpd_tls_security_level | grep -i "may"; then echo "STARTTLS not configured" ; fi
