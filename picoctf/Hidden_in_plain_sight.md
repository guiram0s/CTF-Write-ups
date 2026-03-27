# PicoCTF - Hidden in plainsight Write-up:

## 1. Reconnaissance & Metadata Analysis
The challenge provided an image file (`img.jpg`). Initial enumeration began with analyzing the image's metadata using `exiftool` to look for hidden breadcrumbs or creator notes.

```bash
exiftool img.jpg
```
**Key Discovery:**
Scanning the output revealed a highly suspicious entry in the metadata's `Comment` field:
`Comment : c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9`

---

## 2. Analysis & The Hash Rabbit Hole
At first glance, the alphanumeric string appeared to be a cryptographic hash. However, initial attempts to identify it using `hashid` and `hash-identifier` returned no results. Furthermore, attempting to brute-force the image directly using `stegseek` with the `rockyou.txt` wordlist failed to find a valid passphrase.

Re-evaluating the string, although it lacked the traditional `=` padding, its character set (a randomized mix of uppercase, lowercase, and numbers) strongly suggested **Base64 encoding** rather than a hashed password.

---

## 3. Double-Decoding the Passphrase
Assuming the string was encoded data, I passed it into the Linux command line using the `base64` utility.

**Step 1: First Decode**
```bash
echo "c3RlZ2hpZGU6Y0VGNmVuZHZjbVE9" | base64 -d
```
*Result:* `steghide:cEF6endvcmQ=`

The decoded text provided a massive hint: it explicitly named the steganography tool used (`steghide`) and appended a second Base64 encoded string (this one containing the classic `=` padding).

**Step 2: Second Decode**
I took the second half of the string and decoded it again:
```bash
echo "cEF6endvcmQ=" | base64 -d
```
*Result:* `pAzzword` 
*(Note: The capital 'A' explains why the standard `rockyou.txt` brute-force failed earlier).*

---

## 4. Payload Extraction
With the exact passphrase successfully recovered from the metadata, the final step was to extract the hidden files embedded inside the image.

Using the tool specified in the first decode, I ran the extraction command and passed the passphrase directly via the `-p` flag to avoid any hidden characters or spacing issues:

```bash
steghide extract -sf img.jpg -p "pAzzword"
```

**Result:**
The command successfully authenticated and extracted the hidden payload witht the **flag** from the image, completing the challenge.
