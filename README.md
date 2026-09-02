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
[VSFTPD 2.3.4 Backdoor Exploitation on Metasploitable2](investigations/vsftpd-234-backdoor-metasploitable.md)

## Detections
[SSH Brute-force Detection and Response](detections/ssh-bruteforce-fail2ban-wazuh.md)