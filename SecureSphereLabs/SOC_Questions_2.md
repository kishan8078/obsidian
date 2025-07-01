### **1. What is the role of a SOC analyst?**

A SOC analyst is responsible for monitoring, detecting, analyzing, and responding to cybersecurity threats using tools like SIEM, IDS/IPS, and EDR.

#### 1.1 What tools do SOC analysts commonly use?

- **SIEM tools** like Splunk or QRadar to monitor and correlate logs.
    
- **EDR tools** like CrowdStrike or SentinelOne to track endpoint behavior.
    
- **Packet analyzers** like Wireshark for traffic inspection.
    

#### 1.2 What’s the difference between IDS and EDR?

- **IDS** (e.g., Snort) focuses on detecting threats via network traffic.
    
- **EDR** provides visibility into endpoint behavior (file, registry, process activity).
    

---

### **2. What is a SIEM and how does it help in a SOC?**

SIEM stands for Security Information and Event Management. It collects, aggregates, and analyzes logs to detect security incidents.

#### 2.1 How does SIEM detect anomalies?

SIEMs use:

- **Rules-based detection** (e.g., “failed login attempts > 5”).
    
- **Behavioral analytics** (e.g., UEBA).
    
- **Threat intelligence feeds** to enrich data.
    

#### 2.2 What is log correlation?

It’s the process of **linking events** from different systems to detect complex attack patterns. For example, a login from an unusual IP followed by privilege escalation.

---

### **3. What would you do if an alert says a user logged in from two countries within minutes?**

That’s likely an “impossible travel” scenario indicating potential credential compromise.

#### 3.1 How do you validate such an alert?

- Check **geolocation** of IPs.
    
- Review **VPN or proxy usage**.
    
- Correlate with **user behavior** logs.
    

#### 3.2 What’s the remediation step?

- **Force password reset**.
    
- **Revoke active sessions**.
    
- **Apply or enforce MFA** if missing.
    

---

### **4. What is the CIA triad?**

It refers to:

- **Confidentiality**: Prevent unauthorized access.
    
- **Integrity**: Prevent unauthorized modification.
    
- **Availability**: Ensure reliable access to data.
    

#### 4.1 How are confidentiality, integrity, and availability ensured?

- **Confidentiality**: Encryption, access control, MFA.
    
- **Integrity**: Hashing, checksums, digital signatures.
    
- **Availability**: Backups, failovers, DoS protection.
    

#### 4.2 TLS is used for confidentiality. How does TLS work?

- TLS ensures secure communication using **asymmetric encryption** (RSA/ECDSA) during the handshake to exchange a **shared symmetric key**.
    
- Then, it uses **symmetric encryption** (e.g., AES) for performance and security.
    

#### 4.3 Integrity is achieved by hashing. How does hashing work?

- A **hash function** converts data to a fixed-size string (e.g., SHA-256).
    
- Any change in data alters the hash, making tampering detectable.
    

#### 4.4 How does a TCP handshake happen (before TLS begins)?

- **SYN → SYN-ACK → ACK**: The client sends a SYN, server replies with SYN-ACK, client finishes with ACK. Then secure protocols like TLS can begin.
    

---

### **5. What is the difference between a vulnerability, threat, and risk?**

- **Vulnerability**: Weakness in a system.
    
- **Threat**: Something that exploits a vulnerability.
    
- **Risk**: The likelihood and impact of a threat exploiting a vulnerability.
    

#### 5.1 Give an example scenario.

- **Vulnerability**: Outdated Apache server.
    
- **Threat**: Attacker running an exploit for it.
    
- **Risk**: Data exfiltration if the server is compromised.
    

#### 5.2 How do you calculate risk?

- Using a formula: **Risk = Threat × Vulnerability × Impact**.
    
- Organizations often use **risk matrices** to prioritize.
    

---

### **6. How do you investigate a phishing email?**

Check headers, URLs, attachments, and affected users. Use tools like VirusTotal and sandboxing.

#### 6.1 What do you look for in email headers?

- **Return-path**, **Received from**, and **SPF/DKIM/DMARC** results to verify authenticity.
    

#### 6.2 How do you analyze a suspicious attachment?

- Detonate in a **sandbox**.
    
- Check for **obfuscation**, macros, or executable behavior.
    

---

### **7. What is a zero-day vulnerability?**

A **zero-day** is an undisclosed vulnerability with no available patch, actively exploited or waiting to be.

#### 7.1 How can SOCs detect zero-day attacks?

- Using **behavioral detection**, **threat intelligence**, and **heuristics**, not just signature-based tools.
    

#### 7.2 What are the indicators of zero-day exploitation?

- Unusual system behavior, crash logs, **outbound traffic to C2 servers**, new processes or privilege escalations.
    

---

### **8. What are common network-based attacks a SOC analyst should know?**

Examples:

- **DDoS**, **MITM**, **port scanning**, **DNS poisoning**.
    

#### 8.1 How do you detect port scanning?

- Multiple connection attempts to many ports on one host in a short time. Tools like **Snort** or **Zeek** help detect.
    

#### 8.2 What tools help mitigate these attacks?

- **Firewall rules**, **IPS**, **rate limiting**, and **blackhole routing** for DDoS.
    

---

### **9. What kind of logs do you analyze in a SOC role?**

Authentication logs, firewall logs, web server logs, antivirus, DNS, email gateway, etc.

#### 9.1 What do you look for in authentication logs?

- Failed login attempts, time anomalies, geolocation shifts, new device logins.
    

#### 9.2 What about web server logs?

- 404 floods, long URLs, attempts to access `/admin` or `/etc/passwd`, user-agent anomalies.
    

---

### **10. How do you respond to a ransomware attack?**

Isolate the system, stop spread, find entry point, report, restore from clean backup.

#### 10.1 What logs would you check?

- **File system logs**, **AV/EDR alerts**, **Windows event logs**, **network flows**, and any **C2 communication attempts**.
    

#### 10.2 How do you prevent reinfection?

- Patch vulnerabilities, change passwords, apply least privilege, deploy EDR with rollback features.