# Corridor — THM Web Challenge Write-up

**Challenge Name:** Corridor  
**IP Address:** `10.10.85.247`  
**Category:** Web Exploitation  
**Difficulty:** Easy-Medium  
**Tools Used:** Hashcat, RockYou, md5sum

---

## Initial Recon

After visiting the target IP (`http://10.10.85.247`), I encountered a webpage that displayed a **corridor with multiple doors**. Clicking on each door redirected me to URLs in this format:

```
http://10.10.85.247/<hash>
```

Each path appeared to be in a *hash* format, suggesting an Insecure Direct Object Reference (IDOR) vulnerability using hashed values.

---

## Hash Identification

I extracted one example hash from the URL:  
`c4ca4238a0b923820dcc509a6f75849b`

I used `hashcat` to attempt to crack it:

```bash
hashcat -m 0 -a 0 c4ca4238a0b923820dcc509a6f75849b /usr/share/wordlists/rockyou.txt --force
```

Output:
```
c4ca4238a0b923820dcc509a6f75849b:1
```

This confirmed that the application was hashing numeric values for door identifiers.

---

## Bulk Cracking

I collected the remaining door hashes into a file named `corridor_lab.txt`, then ran:

```bash
hashcat -m 0 -a 0 ~/Desktop/corridor_lab.txt /usr/share/wordlists/rockyou.txt --force
```

### Cracked Hashes:

| Hash                                    | Plaintext |
|-----------------------------------------|-----------|
| c20ad4d76fe97759aa27a0c99bff6710        | 12        |
| 6512bd43d9caa6e02c990b0a82652dca        | 11        |
| c51ce410c124a10e0db5e4b97fc2af39        | 13        |
| 8f14e45fceea167a5a36dedd4bea2543        | 7         |
| eccbc87e4b5ce2fe28308fd9f2a7baf3        | 3         |
| d3d9446802a44259755d38e6d163e820        | 10        |
| 45c48cce2e2d7fbdea1afc51c7c6ad26        | 9         |
| c81e728d9d4c2f636f067f89cc14862c        | 2         |
| 1679091c5a880faf6fb5e6087eb1b2dc        | 6         |
| e4da3b7fbbce2345d7772b0674a318d5        | 5         |
| c9f0f895fb98ab9159f51fd0297e236d        | 8         |
| a87ff679a2f3e71d9181a67b7542122c        | 4         |

---

## IDOR Exploitation

The hashes matched predictable values (`MD5(number)`), so I tested for sensitive endpoints by hashing:

```bash
echo -n "admin.php" | md5sum
# 2a524880b4d504a3da21007051e59146

echo -n "flag.txt" | md5sum
# 159df48875627e2f7f66dae584c5e3a5
```

Neither of these returned anything. Then I tried:

```bash
echo -n "0" | md5sum
# cfcd208495d565ef66e7dff9f98764da
```

Navigating to `http://10.10.85.247/cfcd208495d565ef66e7dff9f98764da` revealed the **flag**.

---

## Final Flag

```
flag{...}
```

---

## Key Takeaways

- IDOR combined with MD5 hashing allowed brute-forcing hidden endpoints.
- Predictable patterns like numeric sequences are dangerous if hashed without extra protection (e.g., salting).
- Hashcat + RockYou is a powerful combo for identifying plaintext values.

