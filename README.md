# Homelab-Journal

Hands-on SOC analyst portfolio: **15+ alert investigations** (phishing, malware, web attacks, threat intel) plus a home SOC lab with a Wazuh SIEM, Sysmon and fail2ban. Written as I prepare for an entry-level SOC analyst role.

**Tools:** VirusTotal · Hybrid Analysis · urlscan.io · Wireshark · tcpdump · Wazuh · Sysmon · MITRE ATT&CK · LetsDefend

## Skills Demonstrated

- Alert triage and True/False Positive decisions, with the evidence behind each call
- IOC enrichment (file hashes, URLs, IPs, domains) across multiple threat-intel sources
- Proxy, endpoint and email log analysis, mapped to MITRE ATT&CK
- Containment and response decisions, including cases where endpoint telemetry was missing
- Detection engineering: Wazuh rules and fail2ban response for SSH brute force
- Clear, evidence-based write-ups with screenshots, timelines, IOCs and recommendations

## SOC Alert Investigations

| Alert | Category | Outcome |
|---|---|---|
| [SOC114 – Malicious Attachment Detected (Phishing)](investigations/soc114-phishing-mail-analysis/SOC114-Malicious-Attachment-Detected-Phishing-Alert.md) | Phishing | Excel attachment chained `excel.exe` → `EQNEDT32.EXE` → `network.exe`; host contained, email deleted |
| [SOC141 – Phishing URL Detected](investigations/soc141-phishing-url-analysis/SOC141-Phishing-URL-Detected.md) | Phishing | True Positive – malicious URL confirmed with VirusTotal and Hybrid Analysis; host contained |
| [SOC146 – Phishing Mail (Excel 4.0 Macros)](investigations/soc146-excel-4.0-macro-phishing/SOC146-excel-4.0-macro-phishing.md) | Phishing | True Positive – macro delivery, C2 URLs in proxy logs, `regsvr32` DLL execution; host contained |
| [SOC104 – Malware Triage (Invoice.exe)](investigations/soc104-malware-triage/SOC104-Malware-Triage-%28Invoice.exe%29.md) | Malware | True Positive – C2 contact confirmed in proxy logs; host contained |
| [SOC109 – Emotet Malware Detected](investigations/soc109-emotet-malware-detected/SOC109-Emotet-Malware-Detected.md) | Malware | True Positive – C2 contact checked and found not accessed |
| [SOC138 – Suspicious Xls File](investigations/soc138-Detected-Suspicious-Xls-File/soc138-Detected-Suspicious-Xls-File.md) | Malware | True Positive – macro-enabled Excel file with a C2 address; host contained |
| [SOC137 – Malicious File/Script Download Attempt](investigations/soc137-malicious-file-download/SOC137-Malicious-File-Download.md) | Malware | True Positive – Triage of a malicious file/script download attempt |
| [SOC119 – Malicious Executable File Detected (+ related SOC104/EventID 84)](investigations/soc119-malicious-executable-file-detected/SOC119-Malicious-Executable-File-Detected.md) | Proxy / Malware | False Positive – legitimate WinRAR download; a 100/100 Hybrid Analysis score discounted with evidence |
| [SOC105 – Threat Intel URL Request (Bitly Shortlink)](investigations/soc105-bitly-shortlink-fp/SOC105-Threat-Intel-URL-Request.md) | Threat intel | False Positive – shortlink checked with VirusTotal, urlscan.io and Hybrid Analysis |
| [SOC165 – Possible SQL Injection Payload](investigations/soc165-possible-sql-injection-payload-detected/SOC165-SQL-Injection-Investigation.md) | Web attack | SQL injection payload analysis |
| [SOC166 – Reflected XSS](investigations/soc166-reflected-XSS-investigation/SOC166-Reflected-XSS-Investigation.md) | Web attack | JavaScript in a requested URL, analysed as reflected XSS |
| [SOC167–170 – Detecting Web Attacks](investigations/soc167-170-detecting-web-attacks/SOC167-170-Detecting-Web-Attacks.md) | Web attack | Command injection (`ls`, `whoami`), IDOR and LFI in web requests |

## Homelab Detections and Exploitation

- [SSH Brute-force Detection and Response](detections/ssh-bruteforce-fail2ban-wazuh.md) – Hydra attack from Kali, detected in Wazuh, banned by fail2ban
- [VSFTPD 2.3.4 Backdoor Exploitation on Metasploitable2](investigations/vsftpd-234-backdoor-metasploitable/vsftpd-234-backdoor-metasploitable.md) – recon, exploitation and network evidence

## Lab Setup

Full build notes: [Homelab Setup](setup-notes/homelab-setup.md)

- **Host:** HP EliteBook 840 G3 (Windows), connected via Wi-Fi to an Airtel ODU router
- **Virtualization:** Oracle VirtualBox, bridged network
- **VMs:**
  - Kali Linux – attacker/tooling box
  - Ubuntu Server – Wazuh-monitored endpoint
  - Wazuh – SIEM manager, collecting and correlating logs
  - Metasploitable – vulnerable target (network-monitored only)
- **Windows host** also runs a Wazuh agent + Sysmon, feeding events into the SIEM

## What I'm Documenting

- SIEM deployment and configuration steps
- Detection rules and alerts I build and tune in Wazuh
- Investigation walkthroughs (simulated incidents, log analysis)
- Tools learned along the way (nmap, Wireshark, tcpdump, ntopng, etc.)

## Goal

Build a public, recruiter-visible record of practical SOC skills while working toward certifications and an entry-level analyst role.
