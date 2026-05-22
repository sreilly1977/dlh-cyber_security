#!/bin/bash
find / -type d -perm -002 2>/dev/null; chmod o-w $(find / -type d -perm -002 2>/dev/null)
