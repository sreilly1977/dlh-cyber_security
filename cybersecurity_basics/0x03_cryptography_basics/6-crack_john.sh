/bin/bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha512 $1 > 6-password.txt
