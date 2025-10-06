# TryHackMe — CyberHeroes (Easy) — Writeup

**Machine / Room:** CyberHeroes (TryHackMe)  
**Target IP:** provided by lab (web login)  
**Author:** Guilherme Ramos 
**Difficulty:** Easy  
**Date:** 2025-10-05

---

## Summary / TL;DR
The web app presented a login form. Initial attempts (LFI, SQL injection) failed. Debugging the client-side code revealed credentials hard-coded in JavaScript. The password in the code was reversed, so reversing it when entering allowed authentication and retrieval of the flag file via an XMLHttpRequest call.

**Root cause:** Client-side authentication logic with hard-coded credentials (and the password stored reversed) — insecure by design for CTF/easy lab purposes.

---

## Recon / Enumeration
- Visited provided IP in a browser.
- Found a simple website with a login form (username + password).
- Attempted standard web vulnerabilities first:
  - Local File Inclusion (LFI) — no success.
  - SQL Injection against login fields — no success.
- Next step: Inspect page source and client-side JavaScript.

---

## Investigation (DevTools)
Opened the browser Developer Tools → *Elements* / *Sources* and inspected `login.html` / linked JS. Found a function bound to the login button that performs authentication on the **client side**. The relevant code (exactly as found) is below:

```html
<script>
    function authenticate() {
      a = document.getElementById('uname')
      b = document.getElementById('pass')
      const RevereString = str => [...str].reverse().join('');
      if (a.value=="h3ck3rBoi" & b.value==RevereString("54321@terceSrepuS")) { 
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
          if (this.readyState == 4 && this.status == 200) {
            document.getElementById("flag").innerHTML = this.responseText ;
            document.getElementById("todel").innerHTML = "";
            document.getElementById("rm").remove() ;
          }
        };
        xhttp.open("GET", "RandomLo0o0o0o0o0o0o0o0o0o0o0gpath12345_Flag_"+a.value+"_"+b.value+".txt", true);
        xhttp.send();
      }
      else {
        alert("Incorrect Password, try again.. you got this hacker !")
      }
</script>
```

**Observations from the code:**
- Username is compared to the literal string `h3ck3rBoi`.
- Password is compared against `RevereString("54321@terceSrepuS")` — i.e., the string `"54321@terceSrepuS"` is reversed before comparison.
- If authentication passes, an XMLHttpRequest GET is made to the file named:
  `RandomLo0o0o0o0o0o0o0o0o0o0o0gpath12345_Flag_<username>_<password>.txt`
  and the response is dumped into the page element with id `flag`.

---

## Exploitation / Steps to get the flag

1. From the JS we know the **username** must be:
   ```
   h3ck3rBoi
   ```
2. The JS constructs the comparison by reversing the literal `"54321@terceSrepuS"`. To pass the check you must enter the **reversed** value in the password field. Reverse the string `"54321@terceSrepuS"` to get the real password you must type.

   - The code uses `RevereString("54321@terceSrepuS")` so perform the reverse:
     - Original in code: `54321@terceSrepuS`
     - Reversed (password to enter): `SuperSecret@12345`

3. Enter credentials in the login form:
   - **Username:** `h3ck3rBoi`
   - **Password:** `SuperSecret@12345`

4. Submit the form. The site performs an XHR request and loads the flag file into the page.

5. The page displays the flag text. Example output (redacted in writeup):
   ```
   Congrats Hacker, you made it !! Go ahead and nail other challenges as well :D flag{........}
   ```

---

## Impact / Notes
- This is a textbook example of **client-side authentication**, which is insecure because all logic and secrets are visible to the user. In a real application this pattern is vulnerable to trivial bypass by inspecting client code.
- The lab intentionally stores credentials client-side to test awareness and debugging skills rather than complex exploitation techniques.
- The reversed password trick adds a small obfuscation hurdle but offers no real security.

---

## Mitigations / How to fix properly
- **Never perform authentication checks on client-side code.** Always verify credentials on the server and establish a secure session token (e.g. server-side session cookie, JWT signed with a secret).
- **Do not store any credential or secret in client-side JavaScript.** Secrets in JS are visible to anyone who inspects the page source or network traffic.
- **Use HTTPS** to protect credentials in transit during a real-world login flow.
- **Implement rate-limiting and account lockout** to protect against brute-force attempts (not relevant for CTF but important in production).

---

## Conclusion / Lessons learned
- When common web vulnerabilities (LFI, SQLi) fail, **inspect client-side code** — sometimes the simplest route is the intended learning path.
- DevTools and viewing page source are powerful first steps in web-CRTL-style challenges.
- Small obfuscation in JS (reversing strings) is not security; always assume JavaScript is visible and untrusted.

---

## Appendix — Things I tried first (quick list)
- Attempted LFI enumeration (no interesting files).
- Attempted SQL injection on login form (no SQLi present).
- Used browser DevTools to find client-side logic and credentials (successful).

---

