# Elixir

<div align=center>
     
    
                                           _______       _    
                                          / __/ (_)_ __ (_)___
                                         / _// / /\ \ // / __/
                                        /___/_/_//_\_\/_/_/   
                                            
                                       Author: B0lg0r0v
                                       https://arthurminasyan.com

</div>

## Table Of Contents

- [Elixir](#elixir)
  * [Description](#description)
  * [Usage](#usage)
  * [Features](#features)
  * [Installation](#installation)
  * [To-Do](#to-do)
  * [Disclaimer](#disclaimer)

## Description
Elixir is a fast multi-function DNS Enumeration, Subdomain Enumeration and Attack Surface Mapping tool. It will try to give you a maximum amount of informations out of a given domain name. <br><br>:warning: *This project is under development and changes will be made frequently*.<br> 
<br>
<p align="center">
  <img width="1100" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/f96bde82-989d-4657-af37-cd4974bed95f">

</p>

## Usage

```
usage: elixir [-h] [-v] [-d DOMAIN] [-l LIST] [-ns NAMESERVER [NAMESERVER ...]] [-a] [-r RECORDS [RECORDS ...]] [-asn] [-rdns RDNS] [-sd] [-sb] [-m] [-z]
              [-s OPTIONS [OPTIONS ...]] [-q]

Elixir

options:
  -h, --help            show this help message and exit
  -v, --version         Version of Elixir
  -d DOMAIN, --domain DOMAIN
                        Target Domain to search for.
  -l LIST, --list LIST  List of domains to search for.
  -ns NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                        Use a custom DNS resolver. Can be used with various combinations incl. subdomain bruteforce and DNS record enumeration.
  -a, --all             All DNS records for the domain.
  -r RECORDS [RECORDS ...], --records RECORDS [RECORDS ...]
                        Search specific DNS records for the domain.
  -asn                  ASN information for the domain.
  -rdns RDNS            Reverse DNS Lookup. Give an IP address.
  -sd, --subdomain      Subdomains of the domain.
  -sb, --subdomain-bruteforce
                        Subdomain bruteforce.
  -m, --map             Attack surface mapping
  -z, --zone-transfer   Attempt a zone transfer.
  -s OPTIONS [OPTIONS ...], --scan OPTIONS [OPTIONS ...]
                        NMAP integration. Add custom queries like the following: elixir -d [DOMAIN] -s " -T4 -sC -sV". You NEED to put a
                        whitespace before your first NMAP argument !
  -q, --quiet           Quiet mode. Disables banner.

Example: elixir -d [DOMAIN] -r TXT A AAAA -s "-T4 -sC -sV" -ns 1.1.1.1
```

## Features
Here's a quick overview of Elixir's features:
  - Attack surface mapping
  - Use custom resolver in conjuction with various arguments
  - DNS zone transfer
  - ASN mapping
  - Subdomain enumeration
  - NMAP integration
  - Update functionality
<br>

## Installation

### Quick Start

In order to grab the latest stable release run:

```
pip3 install elixir
```

### From Source

If you want to have it from source, you can donwload it from the master branch.

```
git clone https://github.com/B0lg0r0v/Elixir.git
cd src
pip3 install -r requirements.txt
python3 entry.py -v
```

## To-Do

- [ ] Add JSON output functionality.
- [ ] Allow the user to supply it's own wordlist for the subdomain bruteforce function.

## Disclaimer

This tool is primarly created for me as a project to enhance my coding skills and start creating some hacking tools. It is not considered to be the most efficient tool out there.<br><br>
Also, you are responsible for any trouble you may cause by using this tool.
