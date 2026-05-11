0-add_user.sh - A bash script that generates a new user and sets a password for that specific user
1-add_group.sh - A bash script that generates a new group, changes the ownership of the file to the new group and sets permissions for it
2-sudo_nopass.sh - A bash script that allows the user to execute the script without entering a password
3-find_files.sh - A bash script that searches for SUID vulnerabilities in a specified directory
4-find_suid.sh - A bash script that lists all files with SUID set in a given directory
5-find_sgid.sh - A bash script that lists all files with SGID set in a given directory
6-check_files.sh - A bash script that Finds all files modified in the last 24 hours with SUID or SGID set and lists detailed information about those files
7-file_read.sh - A bash script that changes the permissions of all files in a directory to read-only for others, without modifying owner or group permissions
8-change_user.sh - A bash script that changes the owner of files in a directory to user3, but only if the current owner is user2
