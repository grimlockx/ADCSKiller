# ADCSKiller - An ADCS Exploitation Automation Tool

ADCSKiller is a Python-based tool designed to automate the exploitation of Active Directory Certificate Services (AD-CS) vulnerabilities. It leverages features of Certipy and Coercer to simplify the process of attacking ADCS infrastructure. Please note that the ADCSKiller is currently in its first drafts and will undergo further refinements and additions in future updates for sure.

## Features
- Exploitation of ESC1
- Exploitation of ESC8

# Usage

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
