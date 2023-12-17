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
Elixir is a fast multi-function DNS Enumeration, Subdomain Enumeration and Attack Surface Mapping tool. It will try to give you a maximum amount of informations out of a given domain name. <br><br>:warning: *This project is under development and changes will be made frequently*.<br> 
<br>
<p align="center">
  <img width="1100" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/34b6b3ae-7aca-448d-ad1e-1a8db52ba328">
</p>

## Usage

```
python3 elixir.py -h
```

<p align="center">
  <img width="2103" alt="grafik" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/8e66ec33-b74d-4568-820e-bea3ff536d21">
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
  - Auto update functionality
<br>

*Examples*:
<br><br>
Subdomain Enumeration:<br>
<p align="center">
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/8721069b-0e2b-4d1b-9a0a-392efc419f63">
</p>
<br><br>

NMAP integration:<br><br>
<p align="center">
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/3303d861-0e7a-426f-8b13-54429e0d8a8a">
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
  <img width="550" alt="image" src="https://github.com/B0lg0r0v/Elixir/assets/115954804/e5b4ea03-c827-4a8e-8bfe-777ec08d625f">
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
