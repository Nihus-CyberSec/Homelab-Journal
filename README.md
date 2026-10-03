# Homelab-Journal
Documentation of my home SOC lab — SIEM setup, detection rules, and investigation write-ups as I prep for a SOC analyst role.

## About This Repo
This is a running journal of my hands-on cybersecurity homelab — setup notes, detection write-ups, and investigation logs as I build practical skills outside of formal work experience.

## Lab Setup
- **Host:** HP EliteBook 840 G3 (Windows), connected via Wi-Fi to an Airtel ODU router
- **Virtualization:** Oracle VirtualBox, bridged network
- **VMs:**
  - Kali Linux — attacker/tooling box
  - Ubuntu Server — Wazuh-monitored endpoint
  - Wazuh — SIEM manager, collecting and correlating logs
  - Metasploitable — vulnerable target (network-monitored only)
- **Windows host** also runs a Wazuh agent + Sysmon, feeding events into the SIEM

## What I'm Documenting
- SIEM deployment and configuration steps
- Detection rules and alerts I build/tune in Wazuh
- Investigation walkthroughs (simulated incidents, log analysis)
- Tools learned along the way (nmap, Wireshark, tcpdump, ntopng, etc.)

## Goal
Build a public, recruiter-visible record of practical SOC skills while working toward certifications and an entry-level analyst role.

## Setup
[Homelab Setup](setup-notes/homelab-setup.md)

## Investigations
- [VSFTPD 2.3.4 Backdoor Exploitation on Metasploitable2](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/vsftpd-234-backdoor-metasploitable/vsftpd-234-backdoor-metasploitable.md)
- [SOC137 — Malicious File/Script Download Attempt](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc137-malicious-file-download/SOC137-Malicious-File-Download.md)
- [SOC165 — Possible SQL Injection Payload Detected](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc165-possible-sql-injection-payload-detected/SOC165-SQL-Injection-Investigation.md)
- [SOC166 — Reflected XSS Investigation](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc166-reflected-XSS-investigation/SOC166-Reflected-XSS-Investigation.md)
- [SOC167-170 — Detecting Web Attacks](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc167-170-detecting-web-attacks/SOC167-170-Detecting-Web-Attacks.md)
- [SOC114 — Malicious Attachment Detected - Phishing Alert](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc114-phishing-mail-analysis/SOC114-Malicious-Attachment-Detected-Phishing-Alert.md)
- [SOC141 — Phishing URL Analysis](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc141-phishing-url-analysis/SOC141-Phishing-URL-Detected.md)
- [SOC146 — Phishing Mail Detected - Excel 4.0 Macros](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc146-excel-4.0-macro-phishing/SOC146-excel-4.0-macro-phishing.md)
- [SOC105 — Requested Threat Intel URL Address (Bitly Shortlink)](https://github.com/Nihus-CyberSec/Homelab-Journal/blob/main/investigations/soc105-bitly-shortlink-fp/SOC105-Requested-T.I.-URL-Address)

## Detections
- [SSH Brute-force Detection and Response](detections/ssh-bruteforce-fail2ban-wazuh.md)