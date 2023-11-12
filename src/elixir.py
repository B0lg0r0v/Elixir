import dns.resolver
import dns.zone
import dns.reversename
from argparse import ArgumentParser
import os
import threading
import nmap
import requests
from multiprocessing import Process
import pyasn

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def list_to_string(string):
    temp = ''.join(string)
    return temp    

def findAllDnsRecords(userInput):
    dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
    server = []
    print(f'\n{bcolors.WARNING}[+] Finding all DNS Records...{bcolors.ENDC}')
    try:
        for dnsRecords in dnsRecordTypes:
            try:
                resolve = dns.resolver.resolve(userInput, dnsRecords)
                for answers in resolve:
                    server.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{dnsRecords}: ' + answers.to_text() + bcolors.ENDC + '\n')
            except dns.resolver.NoAnswer:
                server.append(f'{bcolors.FAIL}{bcolors.BOLD}{dnsRecords}: Record not existing{bcolors.ENDC}\n')
    except dns.resolver.NXDOMAIN:
            print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not exist.{bcolors.ENDC}\n')
    return(list_to_string(server))


def zoneTransfer(userInput):
    hosts = []
    print(f'\n{bcolors.WARNING}[+] Trying Zone Transfer...{bcolors.ENDC}')
    try:
        nsAnswer = dns.resolver.resolve(userInput, 'NS')
        for nsServer in nsAnswer:
            ip = dns.resolver.resolve(nsServer.to_text(), 'A')
            for ipAnswers in ip:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ipAnswers, userInput)))
                    for host in zone:
                        hosts.append(f'\n{bcolors.OKGREEN}{bcolors.BOLD}Found Host for zone transfer: {host}{bcolors.ENDC}')
                except Exception:
                    hosts.append(f'{bcolors.FAIL}NS {bcolors.BOLD}{nsServer} refused the zone transfer.{bcolors.ENDC}\n')
                    continue
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not existing.{bcolors.ENDC}')
    return(list_to_string(hosts))


def findSpecificRecord(userInput, record):
    response = []
    print(f'\n{bcolors.WARNING}[+] Finding {record} Records...{bcolors.ENDC}')
    try:
        for recordType in record:
            try:
                resolve = dns.resolver.resolve(userInput, recordType)
                for answers in resolve:
                    response.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{recordType} Record: {answers.to_text()}{bcolors.ENDC}\n')
            except dns.resolver.NoAnswer:
                response.append(f'{bcolors.FAIL}{bcolors.BOLD}{recordType} Record not existing.{bcolors.ENDC}\n')
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not existing.{bcolors.ENDC}')
    except dns.rdatatype.UnknownRdatatype:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Error in your record statement.{bcolors.ENDC}')
    return(list_to_string(response))


def reverseLookup(ipAddress):
    print(f'\n{bcolors.WARNING}[+] DNS Reverse Lookup...{bcolors.ENDC}')
    dnsNames = []
    try:
        for ips in ipAddress:
            names = dns.reversename.from_address(ips)
            dnsNames.append(f'{bcolors.OKGREEN}{bcolors.BOLD}Reverse Lookup: {str(dns.resolver.resolve(names, "PTR")[0])}{bcolors.ENDC}\n')
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{names} does not existing.{bcolors.ENDC}')
    return(list_to_string(dnsNames))


def subdomainEnumeration(targetDomain):
    print(f'\n{bcolors.WARNING}[+] Subdomain Enumeration started...{bcolors.ENDC}')
    list = []
    with open(f'{os.getcwd()}/../lists/subdomains.txt', 'r') as file:
        name = file.read()
        subDomains = name.splitlines()
    
    for subdomains in subDomains:
        try:
            ipValue = dns.resolver.resolve(f'{subdomains}.{targetDomain}', 'A')
            if ipValue:
                list.append(f'{subdomains}.{targetDomain}')
                if f'{subdomains}.{targetDomain}' in list:
                    print(f'{bcolors.OKGREEN}{bcolors.BOLD}https://{subdomains}.{targetDomain}{bcolors.ENDC}')
                else:
                    pass
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass

def mapDnsRecords(userInput, depth=0):
    dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
    server = []
    indent = '    ' * depth
    print(f'\n{bcolors.WARNING}[+] Mapping the Attack Surface...{bcolors.ENDC}')
    try:
        for dnsRecords in dnsRecordTypes:
            try:
                resolve = dns.resolver.resolve(userInput, dnsRecords)
                for answers in resolve:
                    server.append(f'{bcolors.HEADER}{indent}| {bcolors.OKCYAN}{bcolors.BOLD} {dnsRecords} ----->  ' + answers.to_text() + f'{bcolors.ENDC}')
                    if dnsRecords == 'A':
                        server.extend(f'{bcolors.OKGREEN}{bcolors.BOLD} ----->  ' + f'{geolocation(answers.to_text())}{bcolors.OKBLUE} ----->  {bcolors.UNDERLINE}Origin ASN:{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKBLUE}{asndb.lookup(answers.to_text())[0]}{bcolors.ENDC}, {bcolors.BOLD}{bcolors.OKBLUE}{bcolors.UNDERLINE}BGP Prefix:{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKBLUE}{asndb.lookup(answers.to_text())[1]} {bcolors.ENDC}')
                    if dnsRecords == 'MX':
                        mx = answers.to_text().split(" ")[1]
                        mxIP = dns.resolver.resolve(mx, 'A')
                        server.extend(f'{bcolors.OKGREEN}{bcolors.BOLD} ----->  {bcolors.ENDC}')
                        for u in mxIP:
                            server.extend(f'{bcolors.OKGREEN}{bcolors.BOLD}{u.to_text()} | {bcolors.ENDC}')
                    server.append('\n')
                else:
                    pass
            except dns.resolver.NoAnswer:
                pass

    except dns.resolver.NXDOMAIN:
            pass
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nNo Name Server given or no internet connection.{bcolors.ENDC}')
    
    print("\n" + "-"*50 + "\n")
    print(f'{bcolors.HEADER}{indent}┌── {userInput}{bcolors.ENDC}') 
    print(list_to_string(server))
    return("\n" + "-"*50 + "\n")

def geolocation(ipAddress):

    sendData = requests.get(f'https://ipapi.co/{ipAddress}/json/').json()
    data = {
        'city':sendData.get('city'), 
        'region':sendData.get('region'), 
        'country':sendData.get('country')
    }

    res = 'City: {city}, Region: {region}, Country: {country}'.format(**data)

    return res
    

def serviceDetection(domain):
    print(f'\n{bcolors.WARNING}[+] Scanning ports and services...{bcolors.ENDC}')
    indent = '  '
    temp = []
    scanner = nmap.PortScanner()
    response = dns.resolver.resolve(domain, 'A')
    for answers in response:
        temp.append(answers.to_text()) # If we got multiple IP addresses, we go through each one for a port & service scan.
       
    try:
        for ipAddress in temp:
            print(f'\n ⮑{indent}{bcolors.OKBLUE}{bcolors.BOLD}[+] Scanning ports and services for IP {bcolors.UNDERLINE}{ipAddress}{bcolors.ENDC}{bcolors.OKBLUE}...{bcolors.ENDC}')
            for x in range(15, 450+1):
                res = scanner.scan(ipAddress, str(x))
                res = res['scan'][ipAddress]['tcp'][x]['state']

                if res == 'open':
                    results = scanner.scan(ipAddress, arguments=f'-sV -sC -T4 -p' +str(x))
                    service = (results['scan'][ipAddress]['tcp'][x]['product'])
                    print(f'{indent}  {bcolors.OKGREEN}{bcolors.BOLD}Port {x} is open and is running "{service}".{bcolors.ENDC}')
    except KeyboardInterrupt:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')

def asnLookup(domain):
    print(f'\n{bcolors.WARNING}[+] ASN Lookup for {domain}...{bcolors.ENDC}')
    response = dns.resolver.resolve(domain, 'A')
    for ips in response:
        asn = asndb.lookup(str(ips))
        return f'{bcolors.OKGREEN}{bcolors.BOLD}Origin AS: {asn[0]}, BGP Prefix {asn[1]}{bcolors.ENDC}\n'
    
def reverseAsnLookup(asn):
    print(f'\n{bcolors.WARNING}[+] Reverse ASN Lookup for {asn}...{bcolors.ENDC}')
    values = []
    for x in asn:
        response = asndb.get_as_prefixes(x)
        for u in response:
            print(f'{bcolors.OKGREEN}{bcolors.BOLD}{u}{bcolors.ENDC}')

    return '\n'

if __name__ == '__main__':

    print("\n")
    print("*"*40)
    print(r"""

    _________      _     
   / ____/ (_)  __(_)____
  / __/ / / / |/_/ / ___/
 / /___/ / />  </ / /    
/_____/_/_/_/|_/_/_/     
                         

    Author: B0lg0r0v
    https://root.security
    """)
    print("*"*40+"\n")
        
    
    parser = ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='V0.1-alpha')
    parser.add_argument('-d', '--domain', help='Target Domain to search for.')
    parser.add_argument('-a', '--all', help='Find all DNS Records.', action='store_true')
    parser.add_argument('-r', '--record', help='Search for a specific DNS Record. You can also search for multiple records.', nargs='+')
    parser.add_argument('-asn', '--asn', help='Shows you the origin ASN and the BGP prefix of your target.', action='store_true')
    parser.add_argument('-rasn', '--rasn', help='Shows you the BGP prefixes using an ASN.', nargs='+')
    parser.add_argument('-z', '--zone-transfer', help='Attempts a zone transfer attack.', action='store_true')
    parser.add_argument('-i', '--ip-address', help='Reverse DNS Lookup. You can also put multiple IP addresses.', nargs='+')
    parser.add_argument('-sd', '--subdomains', help='Basic subdomain enumeration.', action='store_true')
    parser.add_argument('-m', '--map', help='Creates a visual representation of the targets infrastructure.', action='store_true')
    parser.add_argument('-s', '--scanning', help='NMAP integration for port scanning & service detection. Works from port 15 up to 450. It needs NMAP to be installed on your system. This module is still under development.', action='store_true')
    parser.epilog = 'Example: python3 dns.py -d root.security -r TXT A AAAA -z'

    args = parser.parse_args()
    asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt') #Initializing the Database for ASN lookup.
    
    try:
                
        if args.domain is not None:
            pass
        
        if args.domain is not None and args.all:
             print(findAllDnsRecords(args.domain))
        elif args.domain is None and args.all:
            parser.error('-d / --domain is required.')
        
        if args.domain is not None and args.record is not None:
            print(findSpecificRecord(args.domain, args.record))
        elif args.domain is None and args.record is not None:
            parser.error('-d / --domain is required.')
        
        if args.zone_transfer and args.domain is not None:
            print(zoneTransfer(args.domain))
        elif args.zone_transfer and args.domain is None:
            parser.error('-d / --domain is required.')

        if args.subdomains and args.domain is not None:
            try:
                for z in range(500):
                    thread = threading.Thread(target=subdomainEnumeration(args.domain)) #Trying different methods for optimization. This one is using the Threading library.
                    thread.start()
            except KeyboardInterrupt:
                print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')
            except dns.resolver.NoNameservers:
                pass
        elif args.subdomains and args.domain is None:
            parser.error('-d / --domain is required.')
            
        if args.map and args.domain is not None:
            print(mapDnsRecords(args.domain))
        elif args.map and args.domain is None:
            parser.error('-d / --domain is required.')

        if args.scanning and args.domain is not None:
            p1 = Process(target=serviceDetection(args.domain)) #Trying different methods for optimization. This one is using the Multiprocessing library.
            p1.start()    
        elif args.scanning and args.domain is None:
            parser.error('-d / --domain is required.')
        
        if args.asn and args.domain is not None:
            print(asnLookup(args.domain))
        elif args.asn and args.domain is None:
               parser.error('-d / --domain is required.')
               
        
        #No need for -d / --domain

        if args.ip_address and args.domain is None:
            print(reverseLookup(args.ip_address))

        if args.rasn and args.domain is None:
            print(reverseAsnLookup(args.rasn))
        
    except ValueError:
        print('Please enter a valid value.')
    
    except dns.exception.SyntaxError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')



