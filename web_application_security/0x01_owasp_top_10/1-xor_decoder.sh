#!/bin/bash
python3 -c "import base64; data=base64.b64decode('${1#\{xor\}}'); key= 0x5F; print(bytes([b ^ key for b in data]).decode())"
