#!/bin/bash
if ! grep -i "smtpd_tls_security_level = may" /etc/postfix/main.cf ; then echo "STARTTLS not configured" ; fi
