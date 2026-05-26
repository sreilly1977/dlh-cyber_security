#!/bin/bash
whois $1 | awk '/Registrant|Admin|Tech/{i=index($0,": "); f=substr($0,1,i-1); v=substr($0,i+2); if(f~/Street/)v=v" "; if(f~/Ext/)f=f":"; print f","v}' > $1.csv
