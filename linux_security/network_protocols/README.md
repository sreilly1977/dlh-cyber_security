0-iptables.sh - A script that displays all current iptables rules in a readable format, including line numbers
1-firewall.sh - A script to set up basic iptables firewall rules that block all incoming traffic except SSH
2-harden.sh - A script to list all world-writable directories and set their permissions to a more secure level
3-identify.sh - A script to check for unpatched common vulnerabilities using lynis audit tool
4-audit.sh - A script to check for and report any non-standard SSH configuration settings in /etc/ssh/sshd_config
5-sshd_config - A secure sshd_config file that follows best practices
6-nfs.sh - A script to scan for NFS shares that are accessible by anyone on the network
7-snmp.sh - A script to find SNMP configurations that allow public access
