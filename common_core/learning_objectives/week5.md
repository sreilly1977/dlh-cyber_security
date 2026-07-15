# Week 5 Learning Objectives

## Nmap Live Host Discovery

**Q: What is Nmap?**
A: Network Scanner used for discovery and security auditing of networks.

**Q: How to use Nmap?**
A: Run `nmap [options] [target]` in terminal/command line.

**Q: How does Nmap scan work?**
A: Sends packets to targets and analyzes responses to map network characteristics.

**Q: What is Subnetworks?**
A: Networks divided into smaller segments using subnet masks for better organization and security.

**Q: How to enumerate Targets?**
A: Use ping scans (`-sn`), ARP scans, or port scans to discover live hosts.

**Q: What is ARP Scan?**
A: Sends ARP requests to local network devices to identify active IP-MAC mappings.

**Q: What is ICMP Echo Scan?**
A: Sends ICMP echo request (ping) packets to check if hosts respond.

**Q: What is ICMP Timestamp Scan?**
A: Sends ICMP timestamp requests to gather timing information from hosts.

**Q: What is ICMP Address Mask Scan?**
A: Queries hosts for their netmask/subnet configuration via ICMP.

**Q: What is TCP SYN Ping Scan?**
A: Sends SYN packets to ports; response indicates live hosts without completing handshakes.

**Q: What is TCP ACK Ping Scan?**
A: Uses ACK packets to probe firewall rules and determine host status.

**Q: What is UDP Ping Scan?**
A: Sends UDP packets to closed/filtered ports to detect live systems.

**Q: What can Nmap detect?**
A: Live hosts, open ports, running services, OS versions, vulnerabilities, and firewall configurations.

**Q: How to scan an IP address with Nmap?**
A: Simply type `nmap 192.168.1.1` replacing with target IP.

**Q: How to check ports with Nmap?**
A: Use `-p [port]` flag like `nmap -p 80,443 192.168.1.1`.

---

## Python for Cybersecurity

**Q: What is the correct way to write a Python script with proper syntax?**
A: Use valid indentation, proper keywords, and end statements with newlines or semicolons.

**Q: What are variables, data types, and operators used for in Python?**
A: They store data, define data structures, and perform logical or arithmetic operations.

**Q: What conditions would you use to implement if, elif, and else statements?**
A: Use `if` for primary checks, `elif` for additional conditions, and `else` for fallback cases.

**Q: What is the difference between a for loop and a while loop, and when do you use each?**
A: Use `for` for iterating over sequences and `while` for repeating until a condition changes.

**Q: What is a function in Python, and how do you define and call it with parameters and return values?**
A: A reusable block defined with `def` that accepts inputs (parameters) and sends back results (`return`).

**Q: What is the socket module used for, and how do you import and use it in a script?**
A: It handles network communication; import with `import socket` and create connections via `socket.socket()`.

**Q: What are Python's built-in functions like input(), print(), len(), and open() used for?**
A: They handle user input, output, length calculation, and file access respectively.

**Q: What do string methods such as .strip(), .split(), and .format() allow you to do?**
A: They remove whitespace, divide strings into lists, and insert values into templates.

**Q: What operations can you perform on Python lists?**
A: Append, extend, remove, slice, sort, and iterate over list elements.

**Q: What command do you use to install Python packages using pip?**
A: Run `pip install package_name` in the terminal.

**Q: What steps are needed to import and use external modules such as dnspython, requests, or beautifulsoup4?**
A: Install via pip, then use `import module_name` at the top of your script.

**Q: What should you look for when reading and understanding Python library documentation?**
A: Look for usage examples, parameter descriptions, return values, and installation instructions.

**Q: What is the proper way to use third-party APIs effectively in Python scripts?**
A: Authenticate properly, handle errors, respect rate limits, and parse responses correctly.

**Q: What methods can you use to read text files using open() and context managers?**
A: Use `with open('file.txt') as f:` followed by `.read()` or `.readline()`.

**Q: What are the correct techniques to write data to files in Python?**
A: Open files in write (`'w'`) or append (`'a'`) mode and use `.write()` or `.writelines()`.

**Q: What is the right way to parse file content line by line?**
A: Iterate over the file object directly inside a `with` block.

**Q: What are the file modes ('r', 'w', 'a'), and what is each one used for?**
A: `'r'` reads, `'w'` overwrites/writes, and `'a'` appends to a file.

**Q: How do you resolve a domain to an IP address in Python?**
A: Use `socket.gethostbyname('domain.com')`.

**Q: What is socket.gethostbyname() used for?**
A: It converts a hostname string into its corresponding IP address.

**Q: What library do you use for advanced DNS queries?**
A: Use `dnspython` for resolving various DNS record types beyond basic IP mapping.

**Q: How do you make an HTTP GET request in Python?**
A: Use `requests.get('url')` from the requests library.

**Q: What library do you use for HTTP requests in Python?**
A: The `requests` library is the standard choice.

**Q: How do you access response headers in Python?**
A: Access them via `response.headers['Header-Name']` after making a request.

**Q: How do you check if a port is open in Python?**
A: Attempt a connection with `socket.connect_ex((ip, port))` and check for `0`.

**Q: What does socket.connect_ex() return for an open port?**
A: It returns `0` if the port is open and accessible.

**Q: What library is used to parse HTML in Python?**
A: `BeautifulSoup` from the `bs4` package is commonly used.

**Q: What is BeautifulSoup used for?**
A: It parses HTML/XML documents to extract and navigate data easily.

**Q: What does .prettify() do?**
A: It formats the parsed HTML string with proper indentation for readability.

**Q: What is web scraping?**
A: Extracting data from websites automatically using code.

**Q: What is web crawling?**
A: Systematically browsing the web to index pages or gather links recursively.

**Q: What is recursion and how is it used in web crawling?**
A: Recursion is a function calling itself; in crawling, it follows links repeatedly to explore sites.

---

## Packet Capture & Network Traffic Analysis

**Q: What is packet capture and why is it important?**
A: Intercepting and logging network traffic for troubleshooting, security analysis, and monitoring.

**Q: How does Wireshark display and dissect network packets?**
A: It decodes each packet's protocols layer by layer, showing headers, flags, and payloads in a structured tree view.

**Q: What is the difference between capture filters and display filters?**
A: Capture filters (BPF syntax) discard unwanted packets during collection; display filters filter visibility after capture without losing data.

**Q: How do you follow TCP streams in Wireshark?**
A: Right-click a packet → Follow → TCP Stream to reconstruct the full conversation between hosts.

**Q: What is tcpdump and when should you use it over Wireshark?**
A: A CLI packet analyzer ideal for headless servers, remote capture, or scripted automation where a GUI isn't available.

**Q: How do you construct effective tcpdump filter expressions?**
A: Use BPF syntax combining primitives like `host`, `port`, `proto`, and logical operators (`and`, `or`, `not`).

**Q: What are common indicators of network anomalies?**
A: Unusual traffic volumes, unexpected ports/protocols, repeated connection attempts, and abnormal DNS lookups.

**Q: How can you identify unauthorized connections in packet captures?**
A: Look for traffic to unknown IPs/domains, unexpected ports, odd communication times, or unrecognized protocols.

**Q: What tools does Wireshark provide for traffic statistics?**
A: Conversations, Endpoints, Protocol Hierarchy, IO Graphs, and Flow Graphs under the Statistics menu.

**Q: How do you analyze DNS queries in network traffic?**
A: Filter for DNS protocol (`udp.port == 53`), examine query names, response codes, and lookup patterns for suspicious activity.

**Q: What are best practices for capturing network traffic?**
A: Capture at the right point, use capture filters to reduce noise, save to disk for offline analysis, and protect sensitive data.

**Q: How does encryption affect traffic analysis?**
A: It hides payload content, forcing analysts to rely on metadata like flow patterns, timing, SNI, and volume rather than packet inspection.
