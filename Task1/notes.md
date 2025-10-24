# Cyber Lab Notes

## 1. Cybersecurity Basics

### CIA Triad

* **Confidentiality** — data is accessible only to authorized parties. (Encrypt data at rest/in transit, access control)

* **Integrity** — data cannot be changed undetectably. (Hashes, signatures, checksums)

* **Availability** — systems and data are available when needed. (Redundancy, backups, DDoS mitigation)

### Common Threat Types

* **Phishing** — trick users into revealing credentials or running malware.

* **Malware** — software designed to harm (virus, worm, trojan, ransomware, spyware).

* **DDoS** — overwhelm services to make them unavailable.

* **SQL Injection** — inject SQL to read/modify database.

* **Brute Force** — try many passwords; mitigations include rate-limiting & account lockout.

* **Ransomware** — encrypts files, demands payment for decryption key.

### Attack Vectors

* **Social Engineering** — manipulation of people (phishing, pretexting).

* **Wireless Attacks** — rogue APs, deauth, WPA cracking (aircrack-ng family).

* **Insider Threats** — malicious or negligent insiders with credentials.

---

## 2. Lab Environment Setup (step-by-step)

**Design principle:** Always isolate your lab from your production/home network. Use Host-Only or an isolated virtual network. No connecting targets to the internet unless you understand the consequences.

### Tools to install

* **Virtualization:** VirtualBox or VMware Workstation / Player
* **Attacker OS:** Kali Linux (VM)
* **Target VMs:** Metasploitable2 (vulnerable Linux VM), DVWA (Damn Vulnerable Web App), or vulnerable Docker containers

### High-level steps (VirtualBox example)

1. Install VirtualBox.
2. Download Kali Linux VM (OVA or ISO) and import / install.
3. Download Metasploitable2 VM (OVA) and import.
4. Create Host-Only network:

   * VirtualBox → File → Host Network Manager → Create (default often `vboxnet0`)
   * Assign network: `192.168.56.0/24` (example). Enable DHCP (optional) or use static IPs.
5. Configure each VM:

   * **Adapter 1:** NAT (optional, for internet on Kali if needed)
   * **Adapter 2:** Host-Only Adapter (`vboxnet0`) — *this isolates lab traffic*
   * For target VMs (DVWA / Metasploitable) you can disable NAT and use only Host-Only.
6. Start VMs. Confirm connectivity:

   * From Kali: `ping 192.168.56.101` (target IP)
   * From Kali: `nmap -sP 192.168.56.0/24` to discover hosts.

---

## 3. Linux Fundamentals

* **File System Navigation:** `cd`, `ls`, `pwd`
* **File & Directory Permissions:** `chmod`, `chown`
* **Package Management:** `apt`, `dpkg`

---

## 4. Networking Basics

### OSI Model (quick)

1. **Physical** — cables, bits
2. **Data Link** — MAC, switches
3. **Network** — IP, routing
4. **Transport** — TCP/UDP
5. **Session** — connections
6. **Presentation** — encryption/encoding
7. **Application** — HTTP, DNS, SMTP

> (When troubleshooting, map tools to layers: Wireshark (1–7), `ping` (3), `traceroute` (3/4), `tcpdump` (2–4).)

### TCP/IP suite

* **IP** — addressing and routing (IPv4, IPv6)
* **TCP** — reliable, connection-oriented (3-way handshake)
* **UDP** — connectionless, lower overhead

### DNS & HTTP/HTTPS

* DNS resolves names to IPs. Lookups: `dig example.com` or `nslookup`
* HTTP uses plaintext. HTTPS uses SSL/TLS for encryption and server authentication.
* Inspect TLS: `openssl s_client -connect example.com:443`

### IP addressing & subnetting (essentials)

* IPv4: `192.168.1.0/24` (mask `255.255.255.0`) → 256 addresses (254 usable)
* `/24` = 8 host bits, `/28` = 4 host bits (16 addresses, 14 usable)
* Convert CIDR to mask: `/24` → `255.255.255.0`, `/16` → `255.255.0.0`
* Example: Given IP `192.168.56.101/24` → network `192.168.56.0` broadcast `192.168.56.255`

### NAT

* Translates private addresses to public. Useful when using NAT+Host-Only across adapters.

---

## 5. Cryptography Basics (hands-on)

### Symmetric vs Asymmetric

* **Symmetric:** same key to encrypt/decrypt (AES). Fast, used for bulk encryption.
* **Asymmetric:** public/private key pair (RSA, ECC). Used for key exchange, signatures.

### Hashing

One-way function. Example commands:

```bash
echo -n "hello" | md5sum   # MD5 (legacy, collision-prone)
echo -n "hello" | sha256sum   # SHA256 (recommended)
```

Use hashing for integrity checks, password storage with salt+iterative hashing (PBKDF2, bcrypt, scrypt, Argon2).

### Digital Certificates & SSL/TLS

* Certificates bind public keys to identities (signed by a CA).
* Use `openssl` to generate test certs and to inspect.

---

## 6. Tool Familiarization — Quick Guide & Example Commands

### Wireshark (packet capture)

* Open GUI, select correct capture interface (host-only interface).
* Capture filter vs display filter:

  * Capture filter (libpcap): `tcp port 80` (applies during capture)
  * Display filter (Wireshark syntax): `http.request`
* To capture from CLI:

```bash
sudo tcpdump -i <iface> -w capture.pcap
```

* Open with Wireshark GUI: `wireshark capture.pcap`
* Inspect handshake: TLS 1.2/1.3 handshake packets, Server Hello, Certificate.

### Nmap (network scanning)

* Host discovery:

```bash
nmap -sn 192.168.56.0/24
```

* Full TCP port scan (fast):

```bash
nmap -sS -T4 -p- 192.168.56.101
```

* Service and version detection:

```bash
nmap -sV -sC 192.168.56.101
```

* OS detection:

```bash
sudo nmap -O 192.168.56.101
```

### Burp Suite (web proxy)

* Proxy intercept: configure browser proxy to `127.0.0.1:8080`
* Intercept requests, modify, forward.
* Use **Repeater** to manually craft and replay requests.
* **Intruder** for automated payloads (Community edition limited).
* **Scanner** available in Professional.

### Netcat (nc) — swiss army knife

* Simple TCP server:

```bash
nc -lvp 4444
```

* Connect to remote:

```bash
nc 192.168.56.101 80
```

* Transfer file:

```bash
# On receiver:
nc -l 1234 > received.bin
# Sender:
nc target 1234 < file.bin
```

### Metasploit (framework)

* Launch `msfconsole`
* Search exploits: `search apache`
* Use an exploit: `use exploit/unix/ftp/vsftpd_234_backdoor`
* Configure `RHOST`, `RPORT`, `PAYLOAD`, then `run` / `exploit`

---


