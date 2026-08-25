# Homelab Setup

## Goal

A small, realistic environment for practicing attack and detection workflows: a vulnerable target, an attacker box, and a SIEM to monitor everything that happens between them.

## Physical/Network Layout

- Home router (Airtel) acts as the gateway, `192.168.1.1`, with multiple devices on the LAN.
- **Windows host** (HP EliteBook 840 G3, 16GB RAM) — the physical machine everything runs on, connected via Wi-Fi. It also runs a Wazuh agent and Sysmon directly (not virtualized), monitoring the host OS itself.
- **Oracle VirtualBox**, running on the Windows host, hosts four VMs, all on a **Bridged Adapter** — meaning each VM gets its own IP directly on the home LAN, as if it were a separate physical device.

| Machine | Role | IP (can shift after reboot) |
|---|---|---|
| Windows host | Physical machine, Wazuh agent + Sysmon | .143 |
| Kali Linux | Attacker box | .118 |
| Ubuntu Server | Wazuh agent target | .168 |
| Wazuh (on Ubuntu-based VM) | SIEM manager + dashboard | .146 |
| Metasploitable2 | Vulnerable target, network-monitored only | .110 |

*(IPs are DHCP-assigned by the router and have shifted after reboots in the past, so I confirm current IPs with `ip a` before each exercise rather than assuming they're fixed.)*

## Wazuh Deployment

- Wazuh manager and dashboard are installed and running.
- **Agent 001** is deployed on the **Windows host** (hostname: `Nnamdi-PC`), alongside **Sysmon** for detailed process/event logging — confirmed flowing into the Wazuh dashboard.
- A second agent is deployed on the **Ubuntu server**, also confirmed reporting.
- **Metasploitable2** doesn't run an agent — it's too old to support one, so I monitor it passively at the network level instead (packet capture, not host telemetry). This means any detection I build involving Metasploitable has to rely on network evidence rather than endpoint logs, which I think is actually a useful constraint to work within.

## Design Notes / Gotchas

- Interface naming isn't consistent across my VMs — the Ubuntu server's interface came up as `enp0s3` (predictable naming), while my other lab machines still use the older `eth0` convention. I ran into this while writing tcpdump commands and now check `ip a` first instead of assuming.
- My lab uses bridged networking, so it's exposed on the home LAN rather than isolated. That's fine for a personal lab, but it's a gap I'm keeping in mind — a "real" environment would need proper segmentation, and I try to note that in my detection/remediation sections where it's relevant.

## Why This Setup

This mirrors, at a small scale, what a SOC analyst deals with day to day: a mix of monitored (agent-based) and unmonitored (network-only) assets, requiring both host-based and network-based detection skills — not just one or the other.
