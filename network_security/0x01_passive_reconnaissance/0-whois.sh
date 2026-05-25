#!/bin/bash
whois $1 | awk 'BEGIN{f=1}{i=index($0,": ");if(i>0){k=substr($0,1,i-1);v=substr($0,i+2);if(k~/Street$/&&v!="")v=v" ";if(k~/Ext$/)k=k":";if(!f)printf"\n";printf"%s,%s",k,v;f=0}}END{printf""}' > $1.csv
