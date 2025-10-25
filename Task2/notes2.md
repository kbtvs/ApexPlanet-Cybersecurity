# ApexPlanet-Cybersecurity
# Task 2 — Network Security & Scanning

## Objective

Learn and demonstrate reconnaissance, port & service scanning, vulnerability assessment, packet analysis, and basic firewall control.

---


## Lab prerequisites & recommended environment

* **Attacker VM:** Kali Linux (recommended).
* **Victim VM:** Metasploitable2 / OWASP Broken Apps / DVWA (recommended).
* **Networking:** Host-Only or Internal network so attacker and victim can communicate but lab stays isolated.
* Tools: `nmap`, `wireshark`, `netcat`, `hping3`, `iptables`, `nessus` (or OpenVAS/GVM).
* Always scan only systems you own or have explicit permission to test.

---

## 1 — Reconnaissance (What & How)

### Passive reconnaissance (no direct contact)

* `whois`, `nslookup`/`dig`, Shodan (web), Google dorking.
* Purpose: collect domain registration, DNS, public service exposure.

Example commands:

```bash
whois example.com
nslookup example.com
dig example.com any
```

**Notes:** Passive recon is lower risk of detection. Use for situational awareness.

### Active reconnaissance (direct interaction)

* Discover hosts and live IPs, banner grabbing.

```bash
# ping sweep to find live hosts
nmap -sn 192.168.56.0/24

# banner grab with netcat
nc -v target_ip 21
```

**Notes:** Active recon is visible to defenders (logging/IDS). Use cautiously; only on allowed targets.

---

## 2 — Port & Service Scanning (Nmap)

### Quick & useful nmap commands

```bash
# Quick SYN scan + service detection (requires sudo for raw sockets)
sudo nmap -sS -sV target_ip -oN nmap/nmap_quick.txt

# Aggressive scan: service detection, OS, scripts
sudo nmap -A -T4 target_ip -oN nmap/nmap_full.txt

# UDP scan (slower)
sudo nmap -sU target_ip -oN nmap/nmap_udp.txt

# Full port range scan and save XML for parsing
sudo nmap -p- -A -oX nmap/nmap_full.xml target_ip
```

---

## 3 — Vulnerability Scanning (Nessus / OpenVAS)

### Nessus scan 

**Host shown:** `192.168.56.101`  
**OS (detected):** Linux Kernel 2.6 on Ubuntu 8.04 (hardy)  
**Scan elapsed:** ~19 minutes  
**Auth:** Fail (scan was UNcredentialed)  
**Total vulnerabilities shown:** 66 (mixed severities)

### Summary
The Nessus scan identifies multiple high-risk and critical issues on the target host. 
- **Critical**
  - Canonical Ubuntu Linux SEoL (end-of-life / unsupported distro) — severe baseline risk.
  - VNC server with `'password'` password (default/weak credential) — remote code / shell risk.
  - SSL Version 2 and 3 protocol detection — insecure/obsolete TLS protocol support.
- **High**
  - `rlogin` service detected — legacy insecure authentication.
  - Samba Badlock vulnerability — remote attack surface for file-sharing.
  - NFS exports world-readable — excessive access permissions.
- **Medium / Mixed**
  - TLS 1.0 detection, unencrypted Telnet, multiple Apache/Tomcat and BIND issues.




---

## 4 — Packet Capture & Analysis (Wireshark)

### Useful display filters (put into `wireshark/wireshark_filters.txt`)

```
# HTTP traffic
http

# DNS
dns

# FTP (control channel)
ftp

# Show only SYNs
tcp.flags.syn == 1 && tcp.flags.ack == 0

# Packets to/from attacker IP
ip.addr == 192.168.56.100
```


### Simulate attack in lab (ONLY in isolated lab)

```bash
# SYN flood simulation (only in isolated lab/network)
sudo hping3 -S --flood -V target_ip -p 80
```

Watch filter `tcp.flags.syn == 1 && tcp.flags.ack == 0` in Wireshark.

---

## 5 — Firewall basics (iptables)

### Demo — Block and Unblock HTTP (port 80) with `iptables` (Complete Steps)

> **Warning:** Run these steps **only** in a lab environment on machines you own or have explicit permission to test. Replace `192.168.56.101` with your actual target IP if different.



#### Environment / Assumptions

* **Attacker (Kali):** will run `nmap` scans.
* **Target (Metasploitable):** will run `iptables` commands.
* Example target IP used below: `192.168.56.101`.



#### 1. Verify port 80 is open (Kali / attacker)

Run on **Kali**:

```bash
# scan only port 80 and save output
sudo nmap -p 80 192.168.56.101 -oN nmap_before_port80.txt

# quick readable check
sudo nmap -p 80 192.168.56.101
```

**Expected output (before blocking):**

```text
PORT   STATE SERVICE
80/tcp open  http
```


#### 2. Add DROP rule on the target (Metasploitable)

Run on **Metasploitable (target)**:

```bash
# append a rule to drop incoming TCP to port 80
sudo iptables -A INPUT -p tcp --dport 80 -j DROP
```

**Notes:**

* `-A` appends the rule to the `INPUT` chain. It takes effect immediately.
* Use `-I INPUT 1` instead of `-A` if you need the rule to be evaluated before other rules.


#### 3. Re-scan port 80 (Kali / attacker) — observe `filtered`

Run on **Kali**:

```bash
# scan port 80 again and save output
sudo nmap -p 80 192.168.56.101 -oN nmap_after_block_port80.txt

# quick readable check
sudo nmap -p 80 192.168.56.101
```

**Expected output (after blocking):**

```text
PORT   STATE    SERVICE
80/tcp filtered http
```

`filtered` indicates probes are being dropped/blocked by a firewall (`iptables`) or filtering device.



#### 4. List `iptables` rules on the target (Metasploitable)

Run on **Metasploitable**:

```bash
# list INPUT chain with line numbers, counters, and no DNS resolution
sudo iptables -L INPUT --line-numbers -n -v
```

Look for a line similar to:

```text
num  pkts bytes target  prot opt in  out source  destination
1    0    0     DROP    tcp  --  any any  0.0.0.0/0  0.0.0.0/0  tcp dpt:80
```

Packet/byte counters should increase when Kali runs scans. This proves the `DROP` rule exists and is being hit by probes.



#### 5. Delete the DROP rule (Metasploitable) — revert change

Run on **Metasploitable**:

```bash
# delete by exact rule spec (safe)
sudo iptables -D INPUT -p tcp --dport 80 -j DROP
```

**Alternative (if you know the line number):**

```bash
# Example: delete rule #1 from INPUT chain (use --line-numbers output to confirm)
sudo iptables -D INPUT 1
```


#### 6. Re-scan port 80 to confirm it's open again (Kali)

Run on **Kali**:

```bash
# scan port 80 again and save output
sudo nmap -p 80 192.168.56.101 -oN nmap_after_unblock_port80.txt

# quick readable check
sudo nmap -p 80 192.168.56.101
```

**Expected output (after removal):**

```text
PORT   STATE SERVICE
80/tcp open  http
```



---







