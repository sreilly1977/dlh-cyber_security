#!/bin/bash
ps ux -u "$1" --no-headers | grep -v ' 0[[:space:]]*0 '
