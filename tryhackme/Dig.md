# TryHackMe - DNS Enumeration

**Machine Name:** DNS Enumeration Challenge
**Difficulty:** Easy  
**Category:** Networking / DNS  
**IP Address:** 10.82.156.247  

---

## Description
This challenge focuses on fundamental DNS enumeration using the `dig` command. The goal is to interrogate a specific, target-hosted DNS server to retrieve a hidden flag associated with the domain `givemetheflag.com`.

---

## Enumeration

### Port Scanning
I started with an aggressive, all-ports TCP `nmap` scan:
```bash
nmap -p- -sV -sC -Pn --min-rate 1000 10.82.156.247
```

**Findings:**
* **Port 22 (SSH):** Open. Running OpenSSH 8.2p1.

*Note: The TCP scan didn't show Port 53 (DNS) because DNS primarily runs over UDP. If a UDP scan (`nmap -sU`) had been run, Port 53 would have shown as open!*

---

## Exploitation: DNS Interrogation

### Initial Testing (Public DNS)
First, I tried a standard `dig` query against the domain:
```bash
dig givemetheflag.com
```
This queried my own local DNS server (`192.168.1.1`), which reached out to the public internet and returned two standard AWS IP addresses (`13.248.169.48` and `76.223.54.146`). Searching those IPs yielded nothing useful.

### Targeted DNS Query (Authoritative Server)
The challenge hinted that the target machine *itself* was the DNS server for this specific domain. I needed to bypass my local DNS resolver and ask the target directly. 

I modified my `dig` command to use the `@` symbol, which forces `dig` to query the target IP directly instead of my default internet provider:
```bash
dig @10.82.156.247 givemetheflag.com A  
```

### Flag Retrieval
Even though the query technically asked for an `A` (IPv4) record, the custom DNS server was specifically configured to reply to this request with a `TXT` (Text) record containing the flag!

```text
;; QUESTION SECTION:
;givemetheflag.com.             IN      A

;; ANSWER SECTION:
givemetheflag.com.      0       IN      TXT     "flag{.....}"
```

---

## Conclusion
This exercise perfectly demonstrates the importance of specifying your DNS resolver during penetration tests. Standard DNS queries will only return public internet records. To find internal networks, hidden subdomains, or CTF flags, you must identify local or custom DNS servers and query them directly using `dig @<target_IP>`.
