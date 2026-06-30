# Web Application Security

A collection of hands-on exercises and CTF challenges focused on web application security testing — covering OWASP vulnerabilities, proxy interception, content discovery, file upload exploitation, and web fuzzing.

## Modules

| Module | Description |
|--------|-------------|
| [`0x01_owasp_top_10`](./0x01_owasp_top_10) | OWASP Top 10 vulnerability identification, including a Bash XOR decoder script and CTF challenge flags |
| [`0x02_burpsuite_fundamentals`](./0x02_burpsuite_fundamentals) | Burp Suite exercises — certificate analysis, response spoofing, Repeater, Interceptor, Sequencer (cookie hijacking), and Decoder |
| [`0x04_content_discovery`](./0x04_content_discovery) | CTF challenges in website crawling, hidden header extraction, hidden directories, DNS subdomain enumeration, virtual host discovery, and fuzzing |
| [`0x05_upload_vulnerabilities`](./0x05_upload_vulnerabilities) | File upload bypass techniques — PHP script upload, null byte extension spoofing, magic number hex editing, and file padding |
| [`0x0B_WEBSEC`](./0x0B_WEBSEC) | ffuf-based CTF challenges — directory/content fuzzing and password cracking |

## Requirements

- Burp Suite (Community or Professional)
- ffuf
- curl
- xxd or hex editor
- Browser with DevTools
