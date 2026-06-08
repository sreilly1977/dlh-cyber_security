#!/bin/bash
# Decode Base64 first, then XOR with WebSphere key pattern
echo "$1" | base64 -d | while IFS= read -r -n1 char; do
    if [ -n "$char" ]; then
        # Get byte value
        printf '%s' "$char" | od -An -tu1 | tr -d ' \n'
    fi
done | xxd -r -p | \
python3 -c "
import sys
data = sys.stdin.buffer.read()
# WebSphere XOR key varies by version - common patterns:
key_bytes = [0x54, 0x7e, 0xe9, 0xa9, 0x8b]  # Typical WebSphere v7/v8
result = ''
for i, byte in enumerate(data):
    result += chr(byte ^ key_bytes[i % len(key_bytes)])
print(result, end='')
"
