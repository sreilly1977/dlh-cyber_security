#!/bin/bash
whois $1 | awk '/Registrant|Admin|Tech/{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$0); split($0,a,":"); field=a[1]; sub(/^[[:space:]]+/,"",field); val=""; for(i=2;i<=length(a);i++){val=val (i>2?":":"") a[i]}; if(field ~ /Street/) val=val " "; print field "," val}' > $1.csv
