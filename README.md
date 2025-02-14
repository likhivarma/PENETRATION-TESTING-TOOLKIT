# PENETRATION-TESTING-TOOLKIT

*COMPANY*: CODTECH IT SOLUTIONS

*NAME*: CHANDRA LEKHA MUTHINENI

*INTERN ID*: CT6WTRE

*DOMAIN*: CYBER SECURITY AND ETHICAL HACKING

*DURATION*: 6 WEEKS

*MENTOR*: NEELA SANTOSH

DESCRIPTION
           This Python-based penetration testing toolkit is designed to help security professionals identify vulnerabilities in networks and web applications. It includes multiple modules for scanning ports, brute-forcing login credentials, detecting web vulnerabilities (SQL Injection & XSS), and sniffing network packets.

Features:-
Port Scanner 
     Scans common ports (22, 80, 443, 3306, 8080) to check if they are open.
     Uses socket connections to detect active services.
     
Brute-Force Attack 
     Attempts to guess the admin password using a wordlist.
     Sends login requests to a target web application.
     
Web Vulnerability Scanner 
     Detects SQL Injection by injecting payloads into URL parameters.
     Checks for XSS vulnerabilities by inserting JavaScript payloads.
      
Network Packet Sniffer 
     Captures raw network packets to analyze data transfers.
     Requires the Scapy library for packet sniffing.

     OUTPUT:-
             [*] Running portscan on localhost
             [*] Scanning target: 127.0.0.1
             [+] Open Port: 8080
             [-] Scan completed.
