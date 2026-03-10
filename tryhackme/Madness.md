# TryHackMe - Madness

**Machine Name:** Madness 

**Difficulty:** Easy/Medium  

**Category:** Steganography / Web Enumeration / Forensics / Privilege Escalation  

**IP Address:** 10.114.160.177  

---

## Description
This challenge focuses on a multi-stage investigation starting from a standard Apache default page. The objective is to identify hidden assets, repair an intentionally corrupted image file signature, brute-force a numerical secret to uncover credentials, perform steganographic extraction to reveal a final obfuscated identity, and finally leverage a vulnerable SUID binary to escalate privileges to root.

---

## Enumeration

### Port Scanning
I started with a full port scan to identify the attack surface:
`nmap -p- -sV -sC -Pn --min-rate 1000 10.114.160.177`

**Findings:**
* **Port 22 (SSH):** Open. Running OpenSSH 7.2p2.
* **Port 80 (HTTP):** Open. Running Apache httpd 2.4.18.

### Web Reconnaissance
Navigating to the web server revealed a standard Apache Ubuntu default page. However, inspecting the page source code (`Ctrl+U`) revealed a hidden comment and an image reference:

```html
<img src="thm.jpg" class="floating_element"/>
<!-- I DIDNT THINK U'D FIND THIS->
```

---

## Image Forensics: Header Repair

### Identifying the Corruption
Upon downloading `thm.jpg`, initial analysis via `exiftool` revealed a critical mismatch. Despite the `.jpg` extension, the file signature indicated a **PNG** file, but one with a missing or corrupted **IHDR** chunk.

Hexadecimal analysis showed the file began with PNG bytes (`89 50 4E 47`) but transitioned into JPEG data structures (`FF DB`) shortly after. The file was a "Frankenstein" image designed to break standard tools.

### Surgical Header Reconstruction
To restore the image to a functional JPEG format, I used `hexeditor` to manually overwrite the corrupted PNG bytes. Opening the file in the editor, I navigated to the first byte and replaced the first 12 bytes with a standard JPEG/JFIF header:

`FF D8 FF E0 00 10 4A 46 49 46 00 01`



This successfully overwrote the fake PNG signature while preserving the rest of the binary data. Once repaired and saved, the image was viewable and contained text pointing to a hidden directory: `/th1s_1s_h1dd3n/`.

---

## Exploitation: The Hidden Secret & The Rabbit Hole

### Numerical Brute Force
Navigating to the new directory revealed a page requesting a "secret" between 0-99. I used a Bash loop to brute-force the URL parameter and identify the correct value:

`for i in {0..99}; do echo -n "Testing $i: "; curl -s "http://10.114.160.177/th1s_1s_h1dd3n/?secret=$i" | grep -v "That is wrong" | grep "Secret Entered" -A 2; done`

**Result:** Testing **73** returned a successful response and what appeared to be a password: `y2RPJ4QaPF!B`.

### Decoding ROT13 (The Username)
The `hidden.txt` file we found earlier contained a clue for the SSH username:
> "Here's a username: **wbxre**. I didn't say I would make it easy for you!"

Following a hint regarding something being "rotTen," I identified this as a **ROT13** cipher.

* **Ciphertext:** `wbxre`
* **Plaintext:** `joker`

### The Real SSH Password
Attempting to SSH with the password found on the web page failed. I got stuck for a long time here and had to check a write up. We had to look to the challenge image and using `steghide` with a *blank* passphrase revealed the true hidden password:

`steghide extract -sf thm.jpg`
*(Hit Enter for no passphrase)*

This revealed the real SSH password: `*axA&GF8dP`

---

## Initial Access

Armed with the correct credentials, I authenticated via SSH:
`ssh joker@10.114.160.177`

Authentication was successful. Listing the home directory revealed the first flag:
`cat user.txt` -> THM{................}

---

## Privilege Escalation (Root)

### Enumerating SUID Binaries
With a foothold established as `joker`, the next goal was horizontal or vertical privilege escalation. I searched the file system for binaries with the SUID bit set (which execute with the permissions of the file owner):

`find / -perm -u=s -type f 2>/dev/null`

The output revealed an interesting, non-standard binary:
`/bin/screen-4.5.0`

### Exploiting GNU Screen 4.5.0 (CVE-2017-5618)
GNU Screen 4.5.0 is known to be vulnerable to a Local Privilege Escalation (LPE) exploit. Searching Exploit-DB (`searchsploit screen 4.5.0`) confirmed the vulnerability and provided a shell script exploit (`linux/local/41154.sh`).

I transferred the `41154.sh` exploit to the target machine via a Python HTTP server, placed it in `/tmp`, made it executable, and ran it:

```bash
chmod +x 41154.sh
./41154.sh
```



The exploit successfully compiled the necessary C payloads, triggered the vulnerability via logfile manipulation, and dropped a root shell (`#`).

### Capturing the Final Flag
Although the shell spawned inside `/etc`, I navigated to the root user's absolute home directory to claim the final flag:

```bash
cd /root
cat root.txt
```

## Conclusion
This box highlighted the importance of manual file forensics (hex editing) when automated tools fail, the dangers of falling for rabbit holes, and the critical risk of leaving vulnerable, outdated SUID binaries (like GNU Screen 4.5.0) on a system. The machine is fully compromised.
