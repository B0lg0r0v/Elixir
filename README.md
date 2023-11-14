# Elixir
<p align="center">
  <img src='https://github.com/B0lg0r0v/elixir/assets/115954804/c71ac078-79cb-44be-9390-633d8ae4384c' width='400'>
</p>

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
Elixir is a fast multi-function DNS Enumeration, Subdomain Enumeration and Attack Surface Mapping tool. It will try to give you a maximum amount of informations out of a given domain name. This project is under development and changes will be made frequently.<br> 
<br>
<p align="center">
  <img width="1100" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/a0bf8871-93f1-4bfa-9e0f-d95f29c5fd6a">
</p>

## Usage
<p align="center">
  <img width="1822" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/a89525e5-9111-419f-acec-39505a056b83">
</p>
<br>
The "-d" argument is required for most of Elixir's functions.<br><br>Example of usage:<br><br>

```
python3 elixir.py -d root.security -r A TXT MX SOA -m -z
```

## Features
Here's a quick overview of Elixir's features:
  - Attack Surface Mapping
  - DNS Zone Transfer
  - ASN Mapping incl. BGP Prefix
  - Subdomain Enumeration
  - NMAP Integration for portscanning & service enumeration (from port 15 up to 450)
<br>

*Examples*:
<br><br>
Subdomain Enumeration:<br>
<p align="center">
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/elixir/assets/115954804/f21e0ecd-424a-4218-889c-55f8a9e637af">
</p>
<br><br>

NMAP integration:<br><br>
<p align="center">
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/elixir/assets/115954804/48c4fe1e-479f-4973-b9b8-1fd74f09d9df">
</p>

## Installation

```
pip3 install -r requirements.txt
```
In order to use the scanning functionality, which contains a NMAP integration, you need to have NMAP installed on your system.<br><br>
Be careful to build the ASN Database in order to use the ASN functionalities:

```
python3 elixir.py -asn-db
```
<p align="center">
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/e5b4ea03-c827-4a8e-8bfe-777ec08d625f">
</p>

## To-Do

- [x] Create an ASN database function in order to always have the latest ASNs.
- [ ] Create an output function.
- [ ] Optimize the subdomain enumeration function.
- [ ] Enhance the NMAP integration with possibility of giving a custom NMAP command as an argument.

## Notes
Credits for the Pyasn module and scripts goes to Hadi Asghar (https://hadiasghari.com) and Arman Noroozian (https://anoroozian.nl/).

## Disclaimer

This tool is primarly created for me as a project to enhance my coding skills and start creating some hacking tools. It is not considered to be the most efficient tool out there.<br><br>
Also, you are responsible for any trouble you may cause by using this tool.
