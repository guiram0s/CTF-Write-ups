# picoCTF Writeup - hashcrack

**Challenge Name:** hashcrack  
**Author:** Nana Ama Atombo-Sackey  
**Category:** Cryptography / Password Cracking  
**Description:**  
A company stored a secret message on a server which got breached due to the admin using weakly hashed passwords.  
Can you gain access to the secret stored within the server?  
Access the server using:
```
nc verbal-sleep.picoctf.net 52014
```

---

## Approach

Upon connecting to the challenge via netcat, we are presented with a hash and prompted to find the corresponding password.

### Step 1: Cracking the First Hash

**Prompted Hash:**  
```
482c811da5d5b4bc6d497ffa98491e38
```

This is a 32-character hash, so we identify it as **MD5**.  
We crack it using Hashcat:

```bash
hashcat -m 0 -a 0 482c811da5d5b4bc6d497ffa98491e38 /usr/share/wordlists/rockyou.txt --force
```

**Result:**
```
482c811da5d5b4bc6d497ffa98491e38:password123
```

Inputting `password123` into the challenge gives:

```
Correct! You've cracked the MD5 hash with no secret found!
Flag is yet to be revealed!! Crack this hash: b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
```

---

### Step 2: Cracking the Second Hash

**Prompted Hash:**  
```
b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3
```

This hash is 40 characters long, so we identify it as **SHA-1**.  
We crack it with:

```bash
hashcat -m 100 -a 0 b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3 /usr/share/wordlists/rockyou.txt --force
```

**Result:**
```
b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3:letmein
```

Inputting `letmein` gives us:

```
Correct! You've cracked the SHA-1 hash with no secret found!
Almost there!! Crack this hash: 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745
```

---

### Step 3: Cracking the Final Hash

**Prompted Hash:**  
```
916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745
```

This is a 64-character hash, indicating **SHA-256**.

```bash
hashcat -m 1400 -a 0 916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745 /usr/share/wordlists/rockyou.txt --force
```

**Result:**
```
916e8c4f79b25028c9e467f1eb8eee6d6bbdff965f9928310ad30a8d88697745:qwerty098
```

Inputting `qwerty098` reveals the **flag**!

---

## Conclusion

This challenge tested basic hash identification and password cracking using Hashcat and the popular `rockyou.txt` wordlist.

**Hashes cracked:**
- MD5 → `password123`
- SHA-1 → `letmein`
- SHA-256 → `qwerty098`

**Tools used:** Hashcat, RockYou wordlist

**Concepts practiced:** Hash types, modes, dictionary attacks, password security
