# Recon 
-------------------------------------------------------------------------------------------------

# Passive Network Reconnaissance:

 # Reverse DNS Lookup: Attempt to resolve the IP address to a domain name. This can give you clues about the organization owning the IP and the services they provide.
    - host <IP_address>
    - dig -x <IP_address>
    - Online Reverse DNS lookup tools:- https://mxtoolbox.com , https://nslookup.com , https://toolbox.googleapps.com/ (it has alot of useful tools)
    
 # Geolocation: Knowing the geolocation, might give an upper hand in passive recon
    - geoiplookup <IP_address> 
    - Online IP Geolocation services (IPinfo.io, MaxMind, etc.)
 
# Active Network Reconnaissance:
 
 # Ping Sweeps: Check if the host is alive and responding to ICMP requests.  Less reliable than in the past, but can provide initial confirmation.
    - ping -c 3 <IP_address> (Send 3 ICMP Echo requests using -c flag)
      - Ping command is often overlooked, it has many userful flags,
       -- "-s" flag with this you can set the size limit of a packet eg. ping -s 30241 target.com
    - fping -g <IP_address>/24` (just ping on steroids)


 # TCP/UDP Port Scanning: This is the bread and butter of recon. Identify open ports to determine the services running on the target.
    - nmap -sT <IP_address>: TCP Connect scan 
    - nmap -sS <IP_address>: TCP SYN scan (stealthier, need root)
    - nmap -sU <IP_address>: UDP scan 
    - nmap -sA <IP_address>: TCP ACK scan (Used to map firewall rulesets by determining whether responses reach target from origin point)
    - nmap -sW <IP_address>: TCP Window scan (Used to find open and filtered TCP ports on Unix systems)
    - nmap -sM <IP_address>: TCP Maimon scan (Must read - https://nmap.org/book/scan-methods-maimon-scan.html)
    - nmap -p- <IP_address>: Scan all 65535 TCP ports (Scan all ports)
    - nmap -F <IP_address>: Fast scan (scans only the most common ports).
    - nmap -v <IP_address>: Verbose output (useful for debugging).
    - nmap -vv <IP_address>:  More verbose!
    - masscan -p1-65535 <IP_address> --rate=1000: (Fast AF, but might be inaccurate & Requires root. Be very careful with rate limiting to avoid causing network issues)
    - nc -zv <IP_address> <port_range>: Simple connection test (Netcat) to enumerate service availibilty.

 # Service and Version Detection: Determine the specific software and version running on each open port.
    - nmap -sV <IP_address>: Version detection
    - nmap -A <IP_address>: Aggressive scan (includes OS detection, version detection, script scanning, and traceroute)
    - Centralops.net , it can be used to scan ports passively

 # O.S Detection: Attempt to fingerprint the target operating system.
    - nmap -O <IP_address>: OS detection
    - nmap --osscan-guess <IP_address>: Attempts to guess OS more aggressively. OS Detection can sometimes give you false positives due to systems masking info

 # Traceroute: Trace the path of packets to the target IP address. Useful for understanding network topology and identifying intermediate hops (firewalls, routers, load balancers, etc)
    - traceroute <IP_address>: Uses UDP packets by default (may be blocked by firewalls).
    - traceroute -T <IP_address>:  Uses TCP SYN packets (more likely to get through firewalls but requires root).
    - traceroute -I <IP_address>:  Uses ICMP Echo Request packets (may be blocked by firewalls).
    - mtr <IP_address>:  Combines traceroute and ping into a continuous display.

 # Firewall Discovery: Determine the presence and rules of firewalls protecting the target.
    - nmap -sN <IP_address>: TCP Null scan.
    - nmap -sF <IP_address>: TCP FIN scan.
    - nmap -sX <IP_address>: TCP Xmas scan.  (These scans attempt to evade firewalls, but results may vary and might be more detectable.)

 # Banner Grabbing: Connect to services directly and attempt to retrieve version information or other details.
    - telnet <IP_address> <port>: Connect to a port and look for banner information after connection
    - nc <IP_address> <port>: 
    - openssl s_client -connect <IP_address>:<port>: If the service is using SSL/TLS – retrieves certificate and TLS version
    - curl -I <IP_address>: Get Http Header banner to get information.

 # Advanced Enumeration & Information Gathering:

   - Nmap Scripting Engine (NSE): A powerful tool for automating advanced reconnaissance tasks.
    - nmap --script vuln <IP_address>:  Run scripts to check for known vulnerabilities.
    - nmap --script default <IP_address>:  Run a set of default scripts (often includes version detection, banner grabbing, and some vulnerability checks).
    - nmap --script <script_name> <IP_address>: Run a specific script (e.g., `nmap --script http-enum <IP_address>` to enumerate web directories).
    - nmap --script=<category> <IP_address>: to list the all availiable scripts within the category.
   - SNMP (Simple Network Management Protocol) Enumeration:  If SNMP is enabled, you can retrieve a wealth of information about the system.
    - snmpwalk -v1 -c public <IP_address>` (Attempt to walk the SNMP tree with the default community string "public").  Change 'public' with available SNMP community.
    - onesixtyone <IP_address>` SNMP community string brute force tool.
   - SMTP Enumeration: Attempt to gather information about valid users and email addresses.
    - nmap --script smtp-enum-users <IP_address> -p 25,465,587
    - smtp-vuln-query`: SMTP Vulnerabilty Checker Tool
    - Manual techniques using the `VRFY`, `EXPN`, or `RCPT TO` commands.
   - SMB Enumeration: Attempt to gather information about shares, users, and other SMB-related details.  Often valuable in mixed (Linux/Windows) environments.
    - nmap --script smb-enum-shares <IP_address> -p 139,445
    - nmap --script smb-enum-users <IP_address> -p 139,445
    - smbclient -L \\\\<IP_address>: (Requires valid credentials or anonymous access)
    - enum4linux 
    - rpcclient -I "" <IP>
   - Firewall Detection:
    - Wafw00f <IP_address>: (Used to detect firewall)

 # Web Ports Reconnaissance (If port 80 or 443 are open):**

   - Web Server Enumeration:
    - nmap --script http-enum <IP_address> -p 80,443: Enumerate common web directories and files.
    - nmap --script http-robots.txt <IP_address> -p 80,443:  Check for `robots.txt` file to identify disallowed directories (potential targets for attacks).
    - nmap --script http-headers <IP_address> -p 80,443: Gather HTTP headers for version information and other details.

 # Directory and File Bruteforcing: (If possible)
    - dirb http://<IP_address>`
    - gobuster dir -u http://<IP_address> -w /path/to/wordlist.txt` (Requires `gobuster` to be installed). -w param specifies the dir word list to be checked again
    - ffuf -u http://<IP_address>/FUZZ -w /path/to/wordlist.txt`  (Similar to gobuster but generally faster and more flexible). -u specifies location - FUZZ the injected point

 # Web Technology Identification: Determine the technologies used on the web server (e.g., programming language, framework, CMS).
    - whatweb <IP_address>: (Attempts to identify the technologies used on a website).
    - wappalyzer: (Browser extension).
    - Builtwith:
    - Burp Suite or OWASP ZAP:

 # Vulnerability Scanning (Web Applications):
    - nikto -h <IP_address>:  Scans for common web server vulnerabilities.
    - nessus` or `OpenVAS: Comprehensive vulnerability scanners (often detect web application vulnerabilities).
    - Manual analysis with Burp Suite or OWASP ZAP to identify vulnerabilities such as SQL injection, XSS, and command injection.

 # DNS Reconnaissance:

   - Zone Transfers: If DNS allows zone transfers (misconfiguration), retrieve all records for the domain.  Extremely useful.
    - dig axfr @<IP_address> <domain>: (Replace `<domain>` with the domain name resolved from the reverse DNS lookup).
    
   - DNS Brute-forcing/Subdomain Enumeration: Attempt to discover subdomains by brute-forcing common names.
    - dnsrecon -d <domain> -D /usr/share/wordlists/dnsmap.txt
    - sublist3r -d <domain>
    - assetfinder --subs-only <domain>: (finds associated subdomains for the given URL and dumps all findings. Requires `go` installed.)
   - Whois Lookup: Gather information about domain registration and ownership.
    - whois <domain>

 # Automated Reconnaissance Frameworks/Tools:

   - Recon-ng: A modular reconnaissance framework with many modules for automating various reconnaissance tasks.
    - Uses modules to automate web scaning
    - Modules used to brute-force sub-domains

   - SpiderFoot:  A comprehensive reconnaissance tool that automates the process of gathering information from various sources.
    -Good in correlating web services that might all be connected by same root admin
    
   - theHarvester: Gathers emails, names, subdomains, IPs, and URLs from various public sources.
    - Easy extraction of user info, for utilization for other vectors.

 # Open Source Intelligence (OSINT): 

 - Search Engines: Use search engines (Google, DuckDuckGo, etc.) to find information about the target organization, its employees, and its infrastructure. Use dorks to get exact infomation
 - Social Media: Investigate social media platforms (LinkedIn, Twitter, Facebook, etc.) to gather information about employees, technologies, and the organization's culture.
 - Code Repositories: Search code repositories (GitHub, GitLab, Bitbucket) for sensitive information, such as API keys, passwords, or configuration files.
 - Paste Sites: Search paste sites (Pastebin, Gist) for sensitive information that may have been leaked.

 # Avoiding Detection (Stealth Techniques):

 - Source IP Rotation:  Use multiple source IP addresses to distribute traffic and avoid being blocked.  Use Proxies and/or VPNs to create another hop
 - User-Agent Randomization:  Use a variety of User-Agent strings to make your traffic look more legitimate. nmap has options for using common or random UAs.
 - Rate Limiting:  Limit the rate at which you send requests to avoid overwhelming the target system and triggering security alerts. Most scanning tools offer options for adjusting the scan rate.
 - Decoy Scans: Use Nmap's `-D` option to add decoy IP addresses to your scans, making it harder to identify your actual source IP address.
 - Tor/ProxyChains: Route your traffic through the Tor network or a chain of proxies to anonymize your source IP address. Be aware that this can significantly slow down your scans.  Remember, using Tor may be against the terms of service of your engagement and raise flags.
 - Idle Scanning: A completely stealthy TCP port scan method that exploits a "zombie" host with a predictable TCP sequence number to perform the scan on your behalf. Very slow and requires a suitable zombie host.
 - Timing Templates:  Use Nmap's timing templates (`-T0` (paranoid) to `-T5` (insane)) to control the speed of your scans. Slower scans are less likely to be detected but take much longer.
 - Evasion Scripts: Nmap has scripts specifically designed to evade firewalls and intrusion detection systems. (Ex `firewalk` and other Firewall evasion techniques)

 # Obscure Techniques:

 - Internet-Wide Scans: Use tools like `shodan` or `censys` which actively scan the entire internet and provide searchable databases of device information. While you're not scanning *from* your IP, the pre-collected data can reveal valuable insights. *Be very careful using this technique – automated and extremely high volume scans of the internet without proper authorization are often illegal.
 - Bluetooth/BLE Recon: In certain targeted situations, mapping Bluetooth/Bluetooth Low Energy (BLE) devices in proximity might offer insights into personnel, security systems, etc. Use tools like `hciconfig` or specialized BLE scanners.
 - RF (Radio Frequency) Mapping:  Detecting and analyzing wireless signals in the vicinity of the target. This can reveal information about Wi-Fi networks, Bluetooth devices, and other radio-based technologies. Requires specialized hardware and expertise.
 - Traffic Analysis of Past Communications: Searching online datasets such as pcap files of various security events. Requires extensive dataset collections.

 # Important Considerations:

 - Legal and Ethical Considerations: *Always* obtain explicit permission before conducting reconnaissance on any system. Be aware of the legal and ethical implications of your actions. Many of the more aggressive scanning techniques can be disruptive or even illegal if performed without authorization.
 - Scope of Engagement: Adhere strictly to the scope defined in your engagement agreement. Don't go beyond the boundaries that have been set.
 - Risk Assessment: Evaluate the potential risks of your actions before you take them. Consider the impact on the target system, the potential for data loss or disruption, and the legal consequences of your actions.
 - Documentation: Document your work thoroughly. Keep detailed records of the steps you took, the tools you used, and the results you obtained.
 - Impact Mitigation: If you discover a critical vulnerability, take steps to mitigate the risk. This may involve contacting the target organization or reporting the vulnerability to the appropriate authorities.

This is an extensive but still not exhaustive list. Keep practicing, experiment with different tools and techniques, and always stay up-to-date with the latest security trends and vulnerabilities. Remember that recon is not just about running tools, but also about *thinking* and connecting the dots between different pieces of information.


# Happy Hacking!!!