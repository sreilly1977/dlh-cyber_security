#!/bin/bash
grep -e "Include" -e "KbdInteractiveAuthentication" -e "UsePAM" -e "X11Forwarding" - e "PrintMotd" -e "AcceptEnv" -e "Subsystem" -e "PasswordAuthentication" -e "PermitRootLogin" -e "AuthorizedKeysFile" -e "TCPKeepAlive" /etc/ssh/sshd_config
