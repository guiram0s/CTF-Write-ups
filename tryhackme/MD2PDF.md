# TryHackMe - MD2PDF

**Machine Name:** MD2PDF  
**Difficulty:** Easy  
**Category:** Web Exploitation  
**IP Address:** 10.10.180.108  

---

## Description

TopTierConversions LTD has released a new web utility: **MD2PDF**, a Markdown-to-PDF conversion tool they proudly claim is "totally secure." This challenge tests our ability to find flaws in how user-submitted content is processed and rendered, particularly in relation to local network restrictions.

---

## Enumeration

### Port Scanning

I began with an `nmap` scan to enumerate open services:

```bash
nmap -sC -sV -p- 10.10.180.108
```

**Findings:**
- Port 80
- Port 5000

---

### Web Exploration (Port 80)

Visiting `http://10.10.180.108` revealed a simple web interface with a **Markdown text box** and a **"Convert to PDF"** button. The client-side JavaScript indicated that the site sends Markdown content to a `/convert` endpoint via a POST request and returns a rendered PDF.

#### Basic Testing

I tested common payloads including:
- Local file inclusion (e.g., `![](/etc/passwd)`)
- Template injections (`{{7*7}}`, `{% include %}`, etc.)
- Code blocks (e.g., triple backticks with shell or HTML content)

However, these returned either **normal PDFs** or **"Bad Request"** errors.

---

## Directory Bruteforcing

I used `gobuster` to enumerate hidden paths:

```bash
gobuster dir -u http://10.10.180.108 -w /usr/share/wordlists/dirb/common.txt
```

**Result:**
- `/admin` → **403 Forbidden**

Accessing it directly showed:

> **Forbidden**  
> This page can only be seen internally (localhost:5000)

---

## Exploitation: SSRF(Server-side request forgery) via Markdown

After research, I discovered that embedded HTML tags are rendered in the PDF. I tested first to check if the PDF renders these as actual HTML elements, not just as plain text, because if so, this tells you HTML passthrough is enabled, which is already a red flag. First test:

```html
<h1>Test</h1>
```
After i made sure it was vulnerable i then attemped:

```html
<iframe src="http://localhost:5000/admin"></iframe>
```

When the PDF was generated, the contents of the internal `/admin` page were included — this is a **classic SSRF** (Server-Side Request Forgery) vulnerability through HTML rendering.

** Flag Obtained:**  
`....{..............}`

---

## Conclusion

This lab illustrates the dangers of rendering untrusted Markdown that supports embedded HTML. The PDF generator processed the iframe server-side, allowing access to otherwise internal services. Validating and sanitizing user input, especially when converting it to other formats like PDF, is crucial.

