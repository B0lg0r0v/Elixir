# Elixir

```
                                                _________      _     
                                               / ____/ (_)  __(_)____
                                              / __/ / / / |/_/ / ___/
                                             / /___/ / />  </ / /    
                                            /_____/_/_/_/|_/_/_/ v0.6    
                                                                         
                                            
                                                Author: B0lg0r0v
                                                https://root.security
```


## Table Of Contents

- [Elixir](#elixir)
  * [Description](#description)
  * [Usage](#usage)
  * [Features](#features)
  * [Installation](#installation)
  * [To-Do](#to-do)
  * [Notes](#notes)
  * [Disclaimer](#disclaimer)

## Description
Elixir is a fast multi-function DNS Enumeration, Subdomain Enumeration and Attack Surface Mapping tool. It will try to give you a maximum amount of informations out of a given domain name. <br><br>:warning: *This project is under development and changes will be made frequently*.<br> 
<br>
<p align="center">
  <img width="1100" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/f96bde82-989d-4657-af37-cd4974bed95f">

</p>

## Usage

```
usage: elixir.py [-h] [-v] [-d DOMAIN] [-l LIST [LIST ...]] [-a]
                 [-r RECORD [RECORD ...]] [-asn-db] [-asn]
                 [-rasn RASN [RASN ...]] [-z] [-i IP_ADDRESS [IP_ADDRESS ...]]
                 [-sd] [-sdo] [-m] [-s] [-o] [-up]

options:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -d DOMAIN, --domain DOMAIN
                        Target Domain to search for.
  -l LIST [LIST ...], --list LIST [LIST ...]
                        File with a list of domains to search for.
  -a, --all             Find all DNS Records.
  -r RECORD [RECORD ...], --record RECORD [RECORD ...]
                        Search for a specific DNS Record. You can also search
                        for multiple records.
  -asn-db, --asn-build  Downloades and creates a Database of ASNs in order to
                        use the ASN Lookup function offline.
  -asn, --asn           Shows you the origin ASN and the BGP prefix of your
                        target. Requires the ASN Database first.
  -rasn RASN [RASN ...], --rasn RASN [RASN ...]
                        Reverse ASN Lookup. Shows you the BGP prefixes using
                        an ASN. Requires the ASN Database first.
  -z, --zone-transfer   Attempts a zone transfer attack.
  -i IP_ADDRESS [IP_ADDRESS ...], --ip-address IP_ADDRESS [IP_ADDRESS ...]
                        Reverse DNS Lookup. You can also put multiple IP
                        addresses.
  -sd, --subdomains     Subdomain brute force using a provided Wordlist. Use
                        this only if you cannot use the "-sdo" argument.
  -sdo, --subdomains-online
                        Subdomain enumeration which uses free online services.
                        Works very fast.
  -m, --map             Attack surface mapping.
  -s, --scanning        NMAP integration for port scanning & service
                        detection. Works from port 15 up to 450. It needs NMAP
                        to be installed on your system.
  -o, --output          Save results in current directory.
  -up, --update         Update Elixir. This will overwrite all your changes,
                        so be careful.

Example: python3 dns.py -d root.security -r TXT A AAAA -z
```

## Features
Here's a quick overview of Elixir's features:
  - Attack Surface Mapping
  - DNS Zone Transfer
  - ASN Mapping incl. BGP Prefix
  - Subdomain Enumeration
  - NMAP Integration for portscanning & service enumeration (from port 15 up to 450)
  - Auto update functionality
<br>

*Examples*:
<br><br>
Subdomain Enumeration:<br>
<p align="center">
  <img alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/88886b66-51f0-4d1d-8ea6-9c0c09289b45">
</p>
<br><br>

NMAP integration:<br><br>
<p align="center">
  <img alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/45403196-e5d4-4a8d-99a2-c301fb3bbc0a">
</p>

## Installation

```
git clone https://github.com/B0lg0r0v/Elixir.git
cd Elixir/src
pip3 install -r requirements.txt
```
In order to use the scanning functionality, which contains a NMAP integration, you need to have NMAP installed on your system.<br><br>
Be careful to build the ASN Database in order to use the ASN functionalities:

```
python3 elixir.py -asn-db
```
<p align="center">
  <img alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/208793f5-996b-4fb5-a66e-ee68c5788ffb">
</p>

## To-Do

- [x] Create an ASN database function in order to always have the latest ASNs.
- [x] Create an output function.
- [x] Optimize the subdomain enumeration function.
- [x] Add an argument to give a list of domains instead of just one domain.
- [ ] Add custom resolver functionality.
- [ ] Enhance the NMAP integration with possibility of giving a custom NMAP command as an argument.

## Notes
Credits for the Pyasn module and scripts goes to Hadi Asghar (https://hadiasghari.com) and Arman Noroozian (https://anoroozian.nl/).

## Disclaimer

This tool is primarly created for me as a project to enhance my coding skills and start creating some hacking tools. It is not considered to be the most efficient tool out there.<br><br>
Also, you are responsible for any trouble you may cause by using this tool.
