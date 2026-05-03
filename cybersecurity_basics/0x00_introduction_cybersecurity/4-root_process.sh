#!/bin/bash
ps u -u "$1" --no-headers | grep -v ' 0[[:space:]]*0 '
