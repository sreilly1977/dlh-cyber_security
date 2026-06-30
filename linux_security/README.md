# Linux Security

A collection of hands-on bash scripting exercises focused on Linux security administration — covering access control, file permissions, network hardening, and system auditing.

## Modules

| Module | Description |
|--------|-------------|
| [`0x00_linux_security_basics`](./0x00_linux_security_basics) | Login monitoring, active/incoming network connections, firewall rule inspection, service enumeration, system auditing, packet capture, and host discovery scanning |
| [`0x01_permissions_sguid_sgid`](./0x01_permissions_sguid_sgid) | User and group management, sudo configuration, SUID/SGID discovery and auditing, and file permission hardening |
| [`0x02_mandatory_access_control`](./0x02_mandatory_access_control) | SELinux mode analysis, AppArmor profile status, SELinux port and user mapping management, and boolean configuration |
| [`network_protocols`](./network_protocols) | iptables firewall setup, SSH hardening, NFS/SNMP/SMTP security auditing, TLS version and cipher testing, HTTP vs HTTPS comparison, and DoS simulation |

## Requirements

- Linux environment (RHEL/CentOS recommended for SELinux modules)
- Bash
- iptables
- nmap
- lynis
- tcpdump
- hping3
- OpenSSL
- SELinux / AppArmor (depending on module)
