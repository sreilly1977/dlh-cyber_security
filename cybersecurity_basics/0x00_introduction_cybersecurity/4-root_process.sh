#!/bin/bash
ps u -u "$1" --no-headers | grep -v -E '^\S+\s+\S+\s+\S+\s+\S+\s+0\s+0\s'
