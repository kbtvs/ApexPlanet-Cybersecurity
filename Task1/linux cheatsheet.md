

## Linux commands

### File system & navigation
- `pwd` — print working directory
- `ls`, `ls -la` — list files (show hidden)
- `cd /path` — change directory
- `mkdir -p dir` — make directory
- `cp src dst`, `mv src dst`, `rm file` / `rm -r dir`

### Permissions & ownership
- `ls -l` — view permissions (`rwxr-xr-x`)
- `chmod 755 file` — change permission
- `chown user:group file` — change owner
- Symbolic permissions: `u,g,o` and `r,w,x`

### Process & services
- `ps aux | grep process`
- `top` / `htop` (install `htop`)
- `systemctl status service`
- `journalctl -u service`

### Package management (Debian/Ubuntu/Kali)
- `sudo apt update`
- `sudo apt upgrade -y`
- `sudo apt install <package> -y`
- `dpkg -l | grep <package>`

### Networking
- `ip addr` — show interfaces and IPs
- `ip route` — routing table
- `ping <ip>`
- `traceroute <ip>`
- `ss -tuln` or `netstat -tuln` — listening ports

### File transfer & remote
- `scp file user@host:/path`
- `ssh user@host`
- `tar -czvf archive.tar.gz folder/`



