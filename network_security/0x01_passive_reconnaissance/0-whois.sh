#!/bin/bash
whois $1 | awk '
BEGIN {
    print "Field,Value"
}
/Registrant Name:/ { print "Registrant Name," $0 }
/Registrant Organization:/ { print "Registrant Org," $0 }
/Registrant Street:/ { gsub(/^[^:]+:/, ""); print "Registrant Street," $0 " " }
/Registrant City:/ { print "Registrant City," $0 }
/Registrant State\/Province:/ { print "Registrant State," $0 }
/Registrant Postal Code:/ { print "Registrant Postal Code," $0 }
/Registrant Country:/ { print "Registrant Country," $0 }
/Registrant Phone:/ { print "Registrant Phone," $0 }
/Registrant Phone Ext:/ { sub(/Phone Ext:/, "Phone Ext:"); print "Phone Ext:," $0 }
/Registrant Email:/ { print "Registrant Email," $0 }
/Admin Name:/ { print "Admin Name," $0 }
/Admin Organization:/ { print "Admin Org," $0 }
/Admin Street:/ { gsub(/^[^:]+:/, ""); print "Admin Street," $0 " " }
/Admin City:/ { print "Admin City," $0 }
/Admin State\/Province:/ { print "Admin State," $0 }
/Admin Postal Code:/ { print "Admin Postal Code," $0 }
/Admin Country:/ { print "Admin Country," $0 }
/Admin Phone:/ { print "Admin Phone," $0 }
/Admin Phone Ext:/ { sub(/Admin Phone Ext:/, "Phone Ext:"); print "Phone Ext:," $0 }
/Admin Email:/ { print "Admin Email," $0 }
/Tech Name:/ { print "Tech Name," $0 }
/Tech Organization:/ { print "Tech Org," $0 }
/Tech Street:/ { gsub(/^[^:]+:/, ""); print "Tech Street," $0 " " }
/Tech City:/ { print "Tech City," $0 }
/Tech State\/Province:/ { print "Tech State," $0 }
/Tech Postal Code:/ { print "Tech Postal Code," $0 }
/Tech Country:/ { print "Tech Country," $0 }
/Tech Phone:/ { print "Tech Phone," $0 }
/Tech Phone Ext:/ { sub(/Tech Phone Ext:/, "Phone Ext:"); print "Phone Ext:," $0 }
/Tech Email:/ { print "Tech Email," $0 }
' > $1.csv
