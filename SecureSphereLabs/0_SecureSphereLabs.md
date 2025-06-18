### ✅ Topics to Learn:

- OSI & TCP/IP Model
- IP addressing, subnetting, CIDR
- Common protocols:
    - HTTP/HTTPS
    - DNS
    - SMTP, POP3, IMAP
    - SSH, FTP, Telnet,
- Packet structure: TCP vs UDP
- NAT, VPN, VLAN
- Common ports & services (e.g., 80, 443, 22, 3389)
- ARP, ICMP, traceroute, ping

### 🔧 Tools:

- **Wireshark**
- **tcpdump**
- **Nmap**
- **Netcat**

---

## 💻 **2. Operating Systems (Windows & Linux)**

You'll analyze events and logs from both OS types.

### ✅ Windows:

- Windows architecture
- Windows Event Logs (Security, Application, System)
- Registry basics
- Common attack artifacts (e.g., WMI abuse, PowerShell, RDP misuse)
- Scheduled tasks and services
- Group Policy basics

### ✅ Linux:

- File system structure
- Commands: `netstat`, `ss`, `top`, `ps`, `journalctl`, `systemctl`
- `/var/log` logs (auth.log, syslog, secure, etc.)
- Cron jobs
- Process and service management

---

## 🔍 **3. Security Information and Event Management (SIEM)**

This is the **heart of a SOC**.

### ✅ Concepts:

- Log ingestion & parsing
- Normalization and enrichment
- Writing correlation rules
- Alert triage and tuning
- Dashboards, searches, queries
- Threat hunting (basic level)

### 🔧 Tools:

- **Splunk**
- **Elastic Stack (ELK)**
- **Wazuh**
- **IBM QRadar**
- **Microsoft Sentinel**

---

## 🛡️ **4. Threat Intelligence**

Used to enrich logs and detect known threats.

### ✅ Concepts:

- IOC (Indicators of Compromise): IPs, domains, hashes
- TTPs (Tactics, Techniques, and Procedures)
- MITRE ATT&CK Framework
- Threat feeds: MISP, AbuseIPDB, OTX, VirusTotal
- STIX/TAXII (standards for threat intel sharing)

---

## 🧠 **5. Malware & Phishing Analysis (Basic Awareness)**

You won’t reverse malware, but should identify its traces.

### ✅ Learn:

- How phishing works (links, attachments, headers)
- Basic email header analysis
- File types and extensions
- Hashing: MD5, SHA256
- Malware indicators: persistence, beaconing, encryption

### 🔧 Tools:

- **VirusTotal**
- **Hybrid Analysis**
- **Any.Run**
- **Joe Sandbox** (if available)

---

## 🛑 **6. Detection and Response**

The process of identifying, investigating, and containing threats.

### ✅ Learn:

- Detection logic (what makes a good alert)
- Use case development
- False positives vs true positives
- Incident Response process (NIST IR lifecycle)
- Escalation criteria
- Basic playbook writing

---

## 🔒 **7. Endpoint Security**

You’ll see alerts from EDR/XDR solutions.

### ✅ Learn:

- Antivirus vs EDR
- EDR telemetry (process tree, command-line arguments)
- Basic PowerShell & command prompt attack detection
- MITRE ATT&CK mappings in EDR

### 🔧 Tools:

- **CrowdStrike Falcon**
- **SentinelOne**
- **Microsoft Defender for Endpoint**
- **Sysmon** (Windows logging agent)

---

## 🧰 **8. IDS/IPS, Firewalls & Proxy**

Traffic-level detection and filtering.

### ✅ Learn:

- How IDS/IPS work (signatures, behavior)
- Firewall rules (accept/deny, NAT)
- Proxy logs: how to read web traffic
- Common alerts (port scanning, DoS, SQLi)

### 🔧 Tools:

- **Snort**, **Suricata**
- **Zeek (Bro)**
- **FortiGate**, **Palo Alto** (if available)
- **Security Onion** (bundled SOC stack)

---

## 💾 **9. Log Analysis and Parsing**

Your bread and butter as a SOC analyst.

### ✅ Learn:

- Log formats (Syslog, JSON, XML, CSV)
- How to identify anomalies
- Windows Event IDs (4624, 4625, 4688, etc.)
- Regex for log parsing
- Writing and tuning detection rules

---

## 📜 **10. Scripting & Automation (Beginner Level)**

Not mandatory but extremely helpful.

### ✅ Learn:

- **Python** or **PowerShell** scripting
- Automating log searches
- Basic SOAR (Security Orchestration and Automation)

---

## ⚖️ **11. Security Frameworks & Compliance**

Used in reports and detection mappings.

### ✅ Learn:

- **MITRE ATT&CK**
- **NIST SP 800-61** (Incident Handling)
- **ISO 27001**
- **GDPR, HIPAA** (if working with compliance)

---


||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||


You can also use this as a learning resources which is important

### 🔐 **1. Credential Attacks**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Brute Force**|Automated login attempts using password guesses.|Multiple failed login attempts (Event ID 4625), from same IP or multiple usernames.|
|**Password Spraying**|Tries a few passwords across many accounts.|Login failures across many accounts with same password.|
|**Credential Stuffing**|Using breached credentials to access accounts.|Failed login followed by success from new IP/device.|

---

### 📧 **2. Phishing & Social Engineering**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Email Phishing**|Malicious emails to trick users into clicking or entering creds.|Suspicious email headers, users clicking known phishing URLs, traffic to known C2 domains.|
|**Spear Phishing**|Targeted phishing at specific individuals.|Unusual sender, spoofed domains, abnormal behavior.|

🛠 Tools for detection: Email gateway logs, VirusTotal, email header analysis, sandboxing.

---

### 🐛 **3. Malware Attacks**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Trojan**|Malware disguised as legitimate software.|Unusual process execution, unknown file hash, network beaconing.|
|**Ransomware**|Encrypts files and demands payment.|Mass file changes, backup deletion, dropped ransom notes, extensions like `.locky`, `.encrypted`.|
|**Keyloggers**|Logs keystrokes secretly.|Suspicious process activity, injection into legitimate processes.|
|**Worms**|Self-replicating malware that spreads via networks.|Sudden traffic spikes, scanning behavior, lateral movement.|

🛠 Tools: EDR logs, Sysmon, AV/EDR alerts, behavioral analysis, sandbox detonation.

---

### 🖥️ **4. Privilege Escalation**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Local Priv Esc**|User escalates to admin via exploits or misconfig.|Use of tools like `whoami`, `net localgroup`, Event IDs 4672, 4688 (suspicious process creation).|
|**Token Impersonation**|Using stolen tokens to impersonate admins.|Unusual logon type (Event ID 4624), impersonation events.|

---

### 🌐 **5. Web-Based Attacks**

|Attack|Description|SOC Indicators|
|---|---|---|
|**SQL Injection**|Injecting SQL to manipulate database queries.|Web server errors, strange query strings, union/select in URLs.|
|**XSS (Cross-Site Scripting)**|Injects scripts into websites viewed by others.|Unusual input in user-agent or query strings.|
|**CSRF**|Forces user to perform unwanted actions.|Harder to detect at SOC unless user reports unusual behavior.|

🛠 Logs: Web server logs, WAF logs, URL inspection.

---

### 🧱 **6. Network Attacks**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Port Scanning**|Mapping open ports on hosts.|Sequential port hits from same IP.|
|**MITM (Man-in-the-Middle)**|Intercepting communications.|SSL certificate mismatch, ARP poisoning alerts.|
|**DNS Poisoning**|Redirecting to malicious IPs via DNS.|Unusual DNS queries/responses, unexpected IP resolutions.|

🛠 Detection: Firewall/IDS logs, Zeek, Suricata, DNS logs.

---

### 🧳 **7. Lateral Movement**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Pass-the-Hash / Pass-the-Ticket**|Reuse of stolen hashes/tickets to move across systems.|Logons using same hash/ticket across machines.|
|**Remote Desktop/SMB abuse**|Using RDP, PsExec, SMB for movement.|Event ID 4624 (Type 10 = RDP), 4648 (explicit creds).|

---

### 🧼 **8. Log & Artifact Cleansing**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Clearing Event Logs**|Hiding attacker activity.|Event ID 1102 (audit log cleared), sudden log gaps.|
|**Timestomping**|Changing timestamps of malicious files.|File creation date older than system build date.|

---

### ⚙️ **9. Command and Control (C2)**

|Attack|Description|SOC Indicators|
|---|---|---|
|**Beaconing**|Malware connects to attacker server periodically.|Regular intervals of outbound connections to strange domains/IPs.|
|**Data Exfiltration**|Sensitive data sent outside.|Unusual outbound traffic volume, zip files to unknown IPs.|

🛠 Tools: Firewall logs, NetFlow, Zeek, PCAP analysis.

---

## 📋 **MITRE ATT&CK Mapping (**

Familiarize yourself with the **MITRE ATT&CK matrix**, which maps:

- **Tactics** (e.g., Initial Access, Persistence)
- **Techniques** (e.g., Valid Accounts, DLL Injection)
- **Sub-techniques** (more detailed methods)

🔗 Link: https://attack.mitre.org/