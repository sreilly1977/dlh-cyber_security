#!/bin/bash
if ! postconf -d /etc/postfix/main.cf smtpd_tls_security_level | grep -i "may"; then echo "STARTTLS not configured" ; fi
