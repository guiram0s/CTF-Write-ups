# TryHackMe - CTF collection Vol.1

**Machine Name:** CTF collection Vol.1

**Difficulty:** Easy / Medium

**Category:** Cryptography / Steganography / Forensics / OSINT

**IP Address:** N/A (Local Files & Web)

## Description
This challenge is a comprehensive 20-flag scavenger hunt designed to test a wide array of CTF skills. The investigation covers everything from basic encoding and metadata analysis to advanced binary reverse-engineering, corrupted file repair, and network traffic analysis.

## Challenge Breakdown

### 1. Enumeration & Simple Decodes
This first set of flags focused on standard encoding and hidden metadata.

* **Flag 01 (Base64):** Decoded `VEhNe2p1NTdfZDNjMGQzXzdoM19iNDUzfQ==` -> `base64 -d`.
* **Flag 02 (Metadata):** Found in image tags via `exiftool Find_me.jpg`.
* **Flag 04 (Visual Manipulation):** Highlighted "blacked out" fields to reveal hidden text(like in the Epstein files).
* **Flag 05 (QR Scan):** Scanned a standard QR code image.
* **Flag 06 (Strings Analysis):** Identified flag embedded in binary junk using `cat` and manual filtering.
* **Flag 07 (Base58):** Decoded via `echo [string] | base58 -d`.
* **Flag 08 (ROT13):** Brute-forced rotation shifts in CyberChef.
* **Flag 09 (Web Source):** Found in HTML comments `<!-- flag -->`.

### Phase 2: Steganography & Cracking
Flags hidden deeper within files using password protection and multi-layer embedding.

* **Flag 03 (Steg Brute Force):** Used `stegseek` with `rockyou.txt` to crack a protected image.
* **Flag 14 (Binary Carving):** Used `binwalk -e hell.jpg` to extract a hidden ZIP archive.
* **Flag 15 (Bit Plane Analysis):** Used `StegSolve` to find text in the Red Plane 0 of a dark image.
* **Flag 16 (Audio Stego):** Flag retrieved from a SoundCloud audio track.

### Phase 3: File Forensics & Header Repair
Manual manipulation of file structures and binary data.

* **Flag 10 (Header Repair):** Fixed a corrupted PNG using `hexeditor -b spoil.png` to repair Magic Bytes.
Checked the first few bytes and compared them against standard file signatures:

JPEG: FF D8 FF

PNG: 89 50 4E 47 0D 0A 1A 0A

GIF: 47 49 46 38 39 61
* **Flag 12 (Esoteric Code):** Decoded Brainfuck logic using CyberChef.
* **Flag 13 (XOR Logic):** XORed two hex strings to reveal the plaintext.
* **Flag 19 (Base Conversion):** Converted Decimal -> Hex -> ASCII.

### Phase 4: Network Analysis & OSINT
External research and traffic inspection.

* **Flag 11 (OSINT):** Recovered deleted data from a Reddit post using external documentation.
* **Flag 17 (Web Archiving):** Used Wayback Machine to view historical webpage data.
* **Flag 18 (Vigenère):** Reversed the key using known plaintext (TRYHACKME) to find key: THM.
* **Flag 20 (PCAP Analysis):** Used Wireshark File -> Export Objects -> HTTP to extract `flag.txt`.

## Conclusion
This machine demonstrates the necessity of a versatile toolkit, moving between terminal-based carving tools and GUI-based protocol analyzers to uncover data hidden across the OSI model.
