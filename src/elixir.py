#----------------- Imports -----------------#
import dns.resolver
import dns.zone
import dns.reversename
from argparse import ArgumentParser
import os
import nmap
import requests
import pyasn
from asn_build.build_asn_db import buildASNdb
import re
import time
import concurrent.futures

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


#----------------- Functions of Elixir -----------------#

def list_to_string(string):
    temp = ''.join(string)
    return temp    

def findAllDnsRecords(userInput):
    dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
    server = []
    serverOutput = []

    print(f'\n{bcolors.WARNING}[+] Finding all DNS Records...{bcolors.ENDC}')
    try:
        for dnsRecords in dnsRecordTypes:
            try:
                resolve = dns.resolver.resolve(userInput, dnsRecords)
                for answers in resolve:
                    server.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{dnsRecords}: ' + answers.to_text() + bcolors.ENDC + '\n')
                    serverOutput.append(f'{dnsRecords}: {answers.to_text()}\n')
            except dns.resolver.NoAnswer:
                server.append(f'{bcolors.FAIL}{bcolors.BOLD}{dnsRecords}: Record not existing{bcolors.ENDC}\n')
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not exist.{bcolors.ENDC}\n')
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')

    if outputBool:
        serverOutput.insert(0, '\n#----------------#\n')
        serverOutput.extend('#----------------#\n')
        outputFunction(list_to_string(serverOutput))
    
    return(list_to_string(server))


def zoneTransfer(userInput):
    hosts = []
    hostsOutput = []
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
                        hostsOutput.append(host + '\n')
                except Exception:
                    hosts.append(f'{bcolors.FAIL}NS {bcolors.BOLD}{nsServer} refused the zone transfer.{bcolors.ENDC}\n')
                    hostsOutput.append(f'{nsServer} refused the zone transfer.\n')
                    continue
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not existing.{bcolors.ENDC}')
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    
    
    if outputBool:
        hostsOutput.insert(0, '\n#----------------#\n')
        hostsOutput.extend('#----------------#\n')
        outputFunction(list_to_string(hostsOutput))
    
    return(list_to_string(hosts))


def findSpecificRecord(userInput, record):
    response = []
    responseOutput = []
    print(f'\n{bcolors.WARNING}[+] Finding {record} Records...{bcolors.ENDC}')
    
    try:
        for recordType in record:
            try:
                resolve = dns.resolver.resolve(userInput, recordType)
                for answers in resolve:
                    response.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{recordType} Record: {answers.to_text()}{bcolors.ENDC}\n')
                    responseOutput.append(f'{recordType} Record: {answers.to_text()}\n')
            except dns.resolver.NoAnswer:
                response.append(f'{bcolors.FAIL}{bcolors.BOLD}{recordType} Record not existing.{bcolors.ENDC}\n')
                responseOutput.append(f'{recordType} Record not existing.\n')

    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{userInput} does not existing.{bcolors.ENDC}')
    except dns.rdatatype.UnknownRdatatype:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Error in your record statement.{bcolors.ENDC}')
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    
    
    if outputBool:
        responseOutput.insert(0, '\n#----------------#\n')
        responseOutput.extend('#----------------#\n')
        outputFunction(list_to_string(responseOutput))    
    
    return(list_to_string(response))


def reverseLookup(ipAddress):
    print(f'\n{bcolors.WARNING}[+] DNS Reverse Lookup...{bcolors.ENDC}')
    dnsNames = []
    dnsNamesOutput = []
    
    try:
        for ips in ipAddress:
            names = dns.reversename.from_address(ips)
            dnsNames.append(f'{bcolors.OKGREEN}{bcolors.BOLD}Reverse Lookup: {str(dns.resolver.resolve(names, "PTR")[0])}{bcolors.ENDC}\n')
            dnsNamesOutput.append(f'Reverse DNS Lookup: {str(dns.resolver.resolve(names, "PTR")[0])}\n')
    except dns.resolver.NXDOMAIN:
        print(f'{bcolors.FAIL}{bcolors.BOLD}{names} does not existing.{bcolors.ENDC}')
        dnsNamesOutput.append(f'{names} does not existing.\n')
    
    
    if outputBool:
        dnsNamesOutput.insert(0, '\n#----------------#\n')
        dnsNamesOutput.extend('#----------------#\n')
        outputFunction(list_to_string(dnsNamesOutput))    
    
    return(list_to_string(dnsNames))


def subdomainEnumeration(targetDomain):
    print(f'\n{bcolors.WARNING}[+] Subdomain Enumeration started...{bcolors.ENDC}')
    list = []
    newList = []
    listOutput = []

    with open(f'{os.getcwd()}/../lists/subdomains.txt', 'r') as file:
        name = file.read()
        subDomains = name.splitlines()

    def enumeration(subdomains):
        try:
            ipValue = dns.resolver.resolve(f'{subdomains.lower()}.{targetDomain}', 'A')
            if ipValue:
                list.append(f'{subdomains.lower()}.{targetDomain}')
                for x in list:
                    if x not in newList: #We check for duplicates
                        newList.append(x)
                        print(f'{bcolors.OKGREEN}{bcolors.BOLD}https://{subdomains.lower()}.{targetDomain}{bcolors.ENDC}')
                        #time.sleep(.01)
                    else:
                        pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.name.EmptyLabel):
            pass
        except KeyboardInterrupt:
            print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')
            executor.shutdown()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        executor.map(enumeration, subDomains)

    if outputBool:   
        listOutput.insert(0, '\n#----------------#\n')
        listOutput.extend('#----------------#\n')
        outputFunction(list_to_string(newList))


def mapDnsRecords(userInput, depth=0):
    dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
    server = []
    indent = '    ' * depth
    print(f'\n{bcolors.WARNING}[+] Mapping the Attack Surface...{bcolors.ENDC}')

    if os.path.exists('../lists/asn_db.txt'):
        asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt')
    else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}ASN DB not existing. Check "-h" argument.{bcolors.ENDC}')

    try:
        for dnsRecords in dnsRecordTypes:
            try:
                resolve = dns.resolver.resolve(userInput, dnsRecords)
                for answers in resolve:
                    server.append(f'{bcolors.HEADER}{indent}| {bcolors.OKCYAN}{bcolors.BOLD} {dnsRecords} ----->  ' + answers.to_text() + f'{bcolors.ENDC}')
                    if dnsRecords == 'A':
                        server.extend(f'{bcolors.OKGREEN}{bcolors.BOLD} ----->  ' + f'{geolocation(answers.to_text(), userInput)}{bcolors.OKBLUE} ----->  {bcolors.UNDERLINE}Origin ASN:{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKBLUE}{asndb.lookup(answers.to_text())[0]}{bcolors.ENDC}, {bcolors.BOLD}{bcolors.OKBLUE}{bcolors.UNDERLINE}BGP Prefix:{bcolors.ENDC} {bcolors.BOLD}{bcolors.OKBLUE}{asndb.lookup(answers.to_text())[1]} {bcolors.ENDC}')            
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
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    except KeyboardInterrupt:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nMapping interrupted.{bcolors.ENDC}')
    
    #print("\n" + "-"*50 + "\n")
    print(f'{bcolors.HEADER}{indent}┌── {userInput}{bcolors.ENDC}') 
    print(list_to_string(server))
    #return("\n" + "-"*50 + "\n")
    return ("")


def geolocation(ipAddress, domain):

    ipSanitazation = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    if ipSanitazation.search(ipAddress):
        
        header = {f'User-Agent': f'keycdn-tools:https://{domain}'}
        sendData = requests.get(f'https://tools.keycdn.com/geo.json?host={ipAddress}', headers=header).json()

        data = {

            'city':sendData.get('data', {}).get('geo', {}).get('city'),
            'region':sendData.get('data', {}).get('geo', {}).get('region_name'),
            'country':sendData.get('data', {}).get('geo', {}).get('country_name'),
            'isp':sendData.get('data', {}).get('geo', {}).get('isp')
            
        }
  
        res = 'City: {city}, Region: {region}, Country: {country}, ISP: {isp}'.format(**data)         
        return res
    
    else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')


def serviceDetection(domain):
    print(f'\n{bcolors.WARNING}[+] Scanning ports and services...{bcolors.ENDC}')
    indent = '  '
    temp = []
    scanner = nmap.PortScanner()
    response = dns.resolver.resolve(domain, 'A')
    serviceOutput = []

    for answers in response:
        temp.append(answers.to_text())  # Use str(answers.address) to get the IP address as a string

    try:
        for ip in temp:
            print(f'\n {bcolors.BOLD}↳{bcolors.ENDC}{indent}{bcolors.OKBLUE}{bcolors.BOLD}[+] Scanning ports and services for IP {bcolors.UNDERLINE}{ip}{bcolors.ENDC}{bcolors.OKBLUE}...{bcolors.ENDC}')
            serviceOutput.append(f'Scanning ports and services for {ip}\n')
            for x in range(15, 30+1):
                res = scanner.scan(ip, str(x))
                state = res['scan'][ip]['tcp'][x]['state']

                if state == 'open':
                    results = scanner.scan(ip, arguments=f'-sV -sC -T4 -p {x}')
                    service = results['scan'][ip]['tcp'][x]['product']      
                    print(f'{indent}  {bcolors.OKGREEN}{bcolors.BOLD}Port {x} is open and is running "{service}".{bcolors.ENDC}')
                    serviceOutput.append(f'{indent}  Port {x} is open and is running "{service}".\n')

    except KeyboardInterrupt:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')
    except KeyError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nError scanning the Host.{bcolors.ENDC}')

    if outputBool:   
        serviceOutput.insert(0, '\n#----------------#\n')
        serviceOutput.extend('#----------------#\n')
        outputFunction(list_to_string(serviceOutput))


def initAsnDB():
    print(f'{bcolors.WARNING}[+] Checking if ASN Database already exists...{bcolors.ENDC}')
    if os.path.exists('../lists/asn_db.txt'):
        response = input(f'{bcolors.WARNING}{bcolors.BOLD}The ASN Database already exists. Do you want to update it? [y] or [n]: {bcolors.ENDC}')
        if response == 'y'.lower():
            buildASNdb()
            print(f'{bcolors.OKGREEN}{bcolors.BOLD}Building Database complete.{bcolors.ENDC}')
        elif response == 'n'.lower():
            print(f'{bcolors.WARNING}{bcolors.BOLD}ASN DB build canceled.{bcolors.ENDC}')
            exit()
    else:
        print(f'{bcolors.OKGREEN}{bcolors.BOLD}Building Database...{bcolors.ENDC}')
        buildASNdb()

    return ""

 
def asnLookup(domain):
    print(f'\n{bcolors.WARNING}[+] ASN Lookup for {domain}...{bcolors.ENDC}')
    asnOutput = []

    try:
        response = dns.resolver.resolve(domain, 'A')
        for ips in response:
            asn = asndb.lookup(str(ips))
            asnOutput.append(f'Origin AS: {asn[0]}, BGP Prefix {asn[1]}\n')
            if outputBool:
                asnOutput.insert(0, '\n#----------------#\n')
                asnOutput.extend('#----------------#\n')
                outputFunction(list_to_string(asnOutput))
            
            return f'{bcolors.OKGREEN}{bcolors.BOLD}Origin AS: {asn[0]}, BGP Prefix {asn[1]}{bcolors.ENDC}\n'
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    
    
    return ""

    
def reverseAsnLookup(asn):
    print(f'\n{bcolors.WARNING}[+] Reverse ASN Lookup for {asn}...{bcolors.ENDC}')
    output = []
    
    for x in asn:
        response = asndb.get_as_prefixes(x)
        for u in response:
            print(f'{bcolors.OKGREEN}{bcolors.BOLD}{u}{bcolors.ENDC}')
            output.append(u)
            output.append('\n')
    
    if outputBool:
        output.insert(0, '\n#----------------#\n')
        output.extend('#----------------#\n')
        outputFunction(list_to_string(output))
    
    return '\n'



def outputFunction(function):
    if os.path.exists('results.txt'):
        f = open('results.txt', 'a')
        f.write(function)
        f.close()
    else:
        f = open('results.txt', 'w+')
        f.write(function)
        f.close()


#----------------- End of Functions of Elixir -----------------#


if __name__ == '__main__':

    print("\n")
    print(r"""

    _________      _     
   / ____/ (_)  __(_)____
  / __/ / / / |/_/ / ___/
 / /___/ / />  </ / /    
/_____/_/_/_/|_/_/_/     
                         

    Author: B0lg0r0v
    https://root.security
    """)
    print("\n")

    #----------------- Sanitazation Variables -----------------#

    domainSanitazation = re.compile('^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
    ipSanitazation = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    #----------------- Process Variables & Global Variables -----------------#

    processList = []
    outputBool = False

    #----------------- Argument Parsing -----------------#  
    
    parser = ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='V0.3-alpha')
    parser.add_argument('-d', '--domain', help='Target Domain to search for.')
    parser.add_argument('-a', '--all', help='Find all DNS Records.', action='store_true')
    parser.add_argument('-r', '--record', help='Search for a specific DNS Record. You can also search for multiple records.', nargs='+')
    parser.add_argument('-asn-db', '--asn-build', help='Downloades and creates a Database of ASNs in order to use the ASN Lookup function offline.', action='store_true')
    parser.add_argument('-asn', '--asn', help='Shows you the origin ASN and the BGP prefix of your target. Requires the ASN Database first.', action='store_true')
    parser.add_argument('-rasn', '--rasn', help='Reverse ASN Lookup. Shows you the BGP prefixes using an ASN. Requires the ASN Database first.', nargs='+')
    parser.add_argument('-z', '--zone-transfer', help='Attempts a zone transfer attack.', action='store_true')
    parser.add_argument('-i', '--ip-address', help='Reverse DNS Lookup. You can also put multiple IP addresses.', nargs='+')
    parser.add_argument('-sd', '--subdomains', help='Basic subdomain enumeration.', action='store_true')
    parser.add_argument('-m', '--map', help='Attack surface mapping.', action='store_true')
    parser.add_argument('-s', '--scanning', help='NMAP integration for port scanning & service detection. Works from port 15 up to 450. It needs NMAP to be installed on your system.', action='store_true')
    parser.add_argument('-o', '--output', help='Save results in current directory.', action='store_true')
    parser.epilog = 'Example: python3 dns.py -d root.security -r TXT A AAAA -z'

    args = parser.parse_args()


    try:
        #----------------- Arguments where DOMAIN is requried -----------------#
                        
        if args.domain is not None:
            pass

        if args.output:         #New output Argument. This will be improved over time and it is currently in testing phase.
               outputBool = True       
        
        if args.domain is not None and args.all:
            if domainSanitazation.search(args.domain):
                print(findAllDnsRecords(args.domain))
            else:
                print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
        elif args.domain is None and args.all:
            parser.error('-d / --domain is required.')
        
        if args.domain is not None and args.record is not None:
            if domainSanitazation.search(args.domain):
                print(findSpecificRecord(args.domain, args.record))
            else:
                print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
        elif args.domain is None and args.record is not None:
            parser.error('-d / --domain is required.')
        
        if args.zone_transfer and args.domain is not None:
            if domainSanitazation.search(args.domain):
                print(zoneTransfer(args.domain))
            else:
                print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
        elif args.zone_transfer and args.domain is None:
            parser.error('-d / --domain is required.')

        #----------------- Function with Process -----------------#
        
        if args.subdomains and args.domain is not None:
            if domainSanitazation.search(args.domain):
                try:
                    #start = time.perf_counter()
                    subdomainEnumeration(args.domain)
                    #stop = time.perf_counter()
                    #print(f'Task completed in {round(stop - start, 2)} seconds.')
       
                except KeyboardInterrupt:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')

                except dns.resolver.NoNameservers:
                    pass
                
                except dns.resolver.NoResolverConfiguration:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
            
            else:
                print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}') 
        
        elif args.subdomains and args.domain is None:
            parser.error('-d / --domain is required.') 

        #---------------------------------------------------------# 

        if args.map and args.domain is not None:
            if domainSanitazation.search(args.domain):
                print(mapDnsRecords(args.domain))
            else:
                print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
        elif args.map and args.domain is None:
            parser.error('-d / --domain is required.')


        #----------------- Function with Process -----------------#

        if args.scanning and args.domain is not None:
            if domainSanitazation.search(args.domain):
                try:
                    #start = time.perf_counter()
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        executor.submit(serviceDetection, args.domain)
                    #stop = time.perf_counter()
                    #print(f'Task completed in {round(stop - start, 2)} seconds.')
                except dns.resolver.NoResolverConfiguration:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}') 
                
                except KeyboardInterrupt:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}\nScanning canceled.{bcolors.ENDC}')
            else:
                 print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
        elif args.scanning and args.domain is None:
            parser.error('-d / --domain is required.')

        #---------------------------------------------------------#

        if args.asn and args.domain is not None:
            if os.path.exists('../lists/asn_db.txt'): 
                asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt') #Initializing the Database for ASN lookup.
                if domainSanitazation.search(args.domain):
                    print(asnLookup(args.domain))
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
            else:
                print(f'{bcolors.WARNING}{bcolors.BOLD}Database could not be initialized.{bcolors.ENDC}')
                asnAnswer = input(f'{bcolors.WARNING}{bcolors.BOLD}ASN Database seems to not exist. Do you want to build it? [y] or [n]: {bcolors.ENDC}')
                if asnAnswer == 'y'.lower():
                    initAsnDB()
                    asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt') #Initializing the Database for ASN lookup.
                    print(asnLookup(args.domain))
                elif asnAnswer == 'n'.lower():
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                    exit()
        elif args.asn and args.domain is None:
            parser.error('-d / --domain is required.')
               
        
        #----------------- Arguments where DOMAIN is NOT requried -----------------#

        if args.ip_address and args.domain is None:
            print(reverseLookup(args.ip_address))

        if args.rasn:
            if os.path.exists('../lists/asn_db.txt'): 
                asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt') #Initializing the Database for rASN lookup.
                print(reverseAsnLookup(args.rasn))
            else:
                print(f'{bcolors.WARNING}{bcolors.BOLD}Database could not be initialized.{bcolors.ENDC}')
                rasnAnswer = input(f'{bcolors.WARNING}{bcolors.BOLD}ASN Database seems to not exist. Do you want to build it? [y] or [n]: {bcolors.ENDC}')
                if rasnAnswer == 'y'.lower():
                    initAsnDB()
                    asndb = pyasn.pyasn(f'{os.getcwd()}/../lists/asn_db.txt') #Initializing the Database for rASN lookup.
                    print(reverseAsnLookup(args.rasn))
                elif rasnAnswer == 'n'.lower():
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                    exit()

        if args.asn_build:
            print(initAsnDB())


    except ValueError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Please enter a valid value.{bcolors.ENDC}')
    
    except dns.exception.SyntaxError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
