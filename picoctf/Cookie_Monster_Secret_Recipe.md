# PicoCTF - Cookie Monster Secret Recipe Write-up:

## 1. Reconnaissance & Initial Access
The challenge provided a target URL that hosted a standard web application login portal. 

To map out the application's behavior, I attempted to authenticate using generic test credentials (e.g., `test` / `test`). Instead of a standard "Invalid Password" error, the application returned a specific hint advising me to "look for cookies."

---

## 2. Web Enumeration
Following the hint, I used the browser's Developer Tools (F12 -> Application/Storage tab) to inspect the active session cookies set by the server. 

I discovered a cookie with a highly suspicious value:
`cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0E2RkEwN0Q4fQ%3D%3D`

---

## 3. Exploitation & Decoding
Analyzing the string, I recognized two distinct encoding methods layered on top of each other:

**Step 1: URL Decoding**
The `%3D%3D` at the end of the string is the URL-encoded representation of `==`. Browsers often encode special characters in cookies to prevent them from breaking HTTP headers. 
I manually URL-decoded the suffix to reconstruct the true string:
`cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0E2RkEwN0Q4fQ==`

**Step 2: Base64 Decoding**
The `==` padding at the end of the string is a universal signature for Base64 encoding. Knowing this, I passed the reconstructed string into the Linux command line using the `base64` decoding utility.

```bash
echo "cGljb0NURntjMDBrMWVfbTBuc3Rlcl9sMHZlc19jMDBraWVzX0E2RkEwN0Q4fQ==" | base64 -d
```

**Result:**
The command successfully decoded the string, outputting the plaintext flag:
`picoCTF{***************************}`
