# ADCSKiller - An ADCS Exploitation Automation Tool

ADCSKiller is a Python-based tool designed to automate the process of discovering and exploiting Active Directory Certificate Services (ADCS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure. Please note that the ADCSKiller is currently in its first drafts and will undergo further refinements and additions in future updates for sure.

![image](https://github.com/grimlockx/ADCSKiller/assets/95048484/e4102251-cd50-4f74-b8c1-578677d35d0c)

## Features
- Enumerate Domain Administrators via LDAP
- Enumerate Domaincontrollers via LDAP
- Enumerate Certificate Authorities via Certipy
- Exploitation of ESC1
- Exploitation of ESC8

## Installation

Since this tool relies on Certipy and Coercer, both tools have to be installed first.

```bash
python3 -V # Needs at least Python 3.7 installed
git clone https://github.com/ly4k/Certipy && pushd Certipy && python3 setup.py install && popd
git clone https://github.com/p0dalirius/Coercer && pushd Coercer && pip install -r requirements.txt && python3 setup.py install && popd
git clone https://github.com/grimlockx/ADCSKiller/ && pushd ADCSKiller && pip install -r requirements.txt && popd
```

## Usage

```bash
Usage: adcskiller.py [-h] -d DOMAIN -u USERNAME -p PASSWORD -t TARGET -l LEVEL -L LHOST

Options:
-h, --help Show this help message and exit.
-d DOMAIN, --domain DOMAIN
                        Target domain name. Use FQDN
-u USERNAME, --username USERNAME
                        Username.
-p PASSWORD, --password PASSWORD
                        Password.
-dc-ip TARGET, --target TARGET
                        IP Address of the domain controller.
-L LHOST, --lhost LHOST
                         FQDN of the listener machine - An ADIDNS is probably required
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
