#!/bin/bash
ps aux --no-headers | grep root | grep -v ' 0[[:space:]]*0 '
