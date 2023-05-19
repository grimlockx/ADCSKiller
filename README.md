# ADCSKiller - An ADCS Exploitation Automation Tool

ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure. Please note that the ADCSKiller is currently in its first drafts and will undergo further refinements and additions in future updates for sure.

![image](https://github.com/grimlockx/ADCSKiller/assets/95048484/55cf9591-d1b5-46eb-b88d-c81fb7650c7e)

## Features
- Enumerate Domain Administrators via LDAP
- Enumerate Domaincontrollers via LDAP
- Enumerate Certificate Authorities via Certipy
- Exploitation of ESC1
- Exploitation of ESC8

## Installation

Since this tool relies on Certipy and Coercer, both tools have to be installed first.

```bash
git clone https://github.com/ly4k/Certipy && cd Certipy && python3 setup.py install
git clone https://github.com/p0dalirius/Coercer && cd Coercer && pip install -r requirements.txt && python3 setup.py install
git clone https://github.com/grimlockx/ADCSKiller/ && cd ADCSKiller && pip install -r requirements.txt
```

## Usage

```bash
Usage: adcskiller.py [-h] -d DOMAIN -u USERNAME -p PASSWORD -t TARGET -l LEVEL -L LHOST

Options:
-h, --help Show this help message and exit.
-d DOMAIN, --domain DOMAIN
    Target domain name. Use the fully qualified domain name (FQDN).
-u USERNAME, --username USERNAME
    Username.
-p PASSWORD, --password PASSWORD
    Password.
-t TARGET, --target TARGET
    Target.
-l LEVEL, --level LEVEL
    Aggressiveness level (1-3).
-L LHOST, --LHOST LHOST
    Local hostname. An ADIDNS entry might be required.
```

## Todos

- [ ] Tests, Tests, Tests
- [ ] Enumerate principals which are allowed to dcsync
- [ ] Use dirkjanm's gettgtpkinit.py to receive a ticket instead of Certipy auth
- [ ] Support DC Certificate Authorities
- [ ] ESC2 - ESC7
- [ ] ESC9 - ESC11?
- [ ] Automated add an ADIDNS entry if required
- [ ] Support DCSync functionality

## Credits

- [Oliver Lyak](https://github.com/ly4k/Certipy "Certipy") for Certipy
- [p0dalirius](https://github.com/p0dalirius/Coercer "Coercer") for Coercer
- [SpecterOps](https://specterops.io/) for their research on ADCS
- [S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t) for bringing these attacks to my screen
