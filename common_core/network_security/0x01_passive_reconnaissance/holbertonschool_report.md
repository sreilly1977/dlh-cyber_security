# Security Scan Report: Holberton School Instance
## Domain
- **Name**: `holbertonschool.com`
- **IP Address**: `198.202.211.1`

##Subdomain##
## General Information
- **Hostname**: `ec2-52-47-143-83.eu-west-3.compute.amazonaws.com`
- **IP Address**: `52.47.143.83`
- **Custom Domain**: `yriry2.holbertonschool.com`
- **Cloud Provider**: Amazon (AWS)
- **Region**: `eu-west-3` (Paris, France)
- **Service**: EC2
- **Organization**: Amazon Data Services France
- **ISP**: Amazon.com, Inc.
- **ASN**: AS16509

## Web Technologies
- **Reverse Proxy**: Nginx 1.21.6
- **Web Server**: Nginx 1.21.6

## Open Ports & Services
| Port | Protocol | Status | Details |
|------|----------|--------|---------|
| 80   | TCP      | Active | 301 Redirect to HTTPS (`yriry2.holbertonschool.com`) |
| 443  | TCP      | Active | HTTPS (Discourse Forum) |

### HTTP 80 Response
```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.21.6
Date: Wed, 20 May 2026 10:48:40 GMT
Location: https://yriry2.holbertonschool.com/

## HTTPS 443 Response (Key Headers)
```http
HTTP/1.1 200 OK
Server: nginx
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
Content-Security-Policy: upgrade-insecure-requests; base-uri 'self'; ...

## SSL Certificate Details
| Field | Value |
| :--- | :--- |
| **Issuer** | Let's Encrypt (E8) |
| **Subject** | CN=yriry2.holbertonschool.com |
| **Not Before** | May 4, 2026 |
| **Not After** | Aug 2, 2026 |
| **Algorithm** | ECDSA with SHA384 |
| **Public Key** | P-256 (prime256v1) |
| **SAN** | DNS:yriry2.holbertonschool.com |

## Identified Vulnerabilities

### 1. CVE-2025-23419 (Severity: 5.3)
- **Description**: TLS session resumption bypass in Nginx when multiple server blocks share IP/port with client certificate auth.
- **Affected Config**: TLS Session Tickets or SSL session cache enabled in default server.
- **Mitigation**: Disable session tickets/cache or isolate client-auth servers.

### 2. CVE-2023-44487 (Severity: 7.5)
- **Description**: HTTP/2 Rapid Reset DoS attack (exploited Aug-Oct 2023).
- **Impact**: Server resource exhaustion via rapid stream resets.
- **Mitigation**: Update Nginx to patched version; implement rate limiting.
