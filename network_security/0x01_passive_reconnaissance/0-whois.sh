#!/bin/bash
whois $1 | awk '/Registrant|Admin|Tech/ && !/information on how to contact/{split($0,a,":"); gsub(/^[ ,]+|[ ,]+$/, "", a[1]); v=a[2]; sub(/^[ ,]+/, "", v); if(a[1]~/Registry.*ID/)next; if(a[1]~/Street/)v=v" "; if(a[1]~/Ext/)a[1]=a[1]":"; sep=(v~/ /?", ":""); print a[1]sep v}' > $1.csv
