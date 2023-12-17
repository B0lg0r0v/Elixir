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
from core.subdomain import onlineSubdomains, bruteForceSubdomains
from core.dnsfunc import dnsEnumeration
import re
import concurrent.futures
import json
import time

#---------------------------------------------------------# 

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


def zoneTransfer(userInput):
    hosts = []
    hostsOutput = []
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
        outputFunction(list_to_string(hostsOutput), userInput)
    
    return(list_to_string(hosts))


def mapDnsRecords(userInput, depth=0):
    dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
    server = []
    indent = '    ' * depth
    print(f'\n{bcolors.WARNING}[+] Mapping the Attack Surface...{bcolors.ENDC}')

    if os.path.exists(asnDbPath):
        asndb = pyasn.pyasn(asnDbPath)
    else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}ASN DB not existing. Check "-h" argument.{bcolors.ENDC}')

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
    except (dns.resolver.NoResolverConfiguration, dns.resolver.LifetimeTimeout):
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    except KeyboardInterrupt:
        print(f'{bcolors.FAIL}{bcolors.BOLD}\nMapping interrupted.{bcolors.ENDC}')
    
    #print("\n" + "-"*50 + "\n")
    print(f'{bcolors.HEADER}{indent}┌── {userInput}{bcolors.ENDC}') 
    print(list_to_string(server))
    #return("\n" + "-"*50 + "\n")
    return ""


def geolocation(ipAddress):

    ipSanitazation = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    
    if ipSanitazation.search(ipAddress):
        
        response = requests.get(f'http://ip-api.com/json/{ipAddress}') #Using http instead of https because of the free API. You may want to change that.
        data = response.json()

        if response.status_code == 200:
            city = data.get('city')
            region = data.get('regionName')
            country = data.get('country')
            isp = data.get('isp')

            res = f'City: {city}, Region: {region}, Country: {country}, ISP: {isp}'
            return res
        else:
            print(f'Error: {data.get("message")}')
    
    else:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')


def serviceDetection(domain):
    indent = '  '
    temp = []
    scanner = nmap.PortScanner()
    response = dns.resolver.resolve(domain, 'A')
    serviceOutput = []

    for answers in response:
        temp.append(answers.to_text()) 

    try:
        for ip in temp:
            print(f'\n {bcolors.BOLD}↳{bcolors.ENDC}{indent}{bcolors.OKBLUE}{bcolors.BOLD}[+] Scanning ports and services for IP {bcolors.UNDERLINE}{ip}{bcolors.ENDC}{bcolors.OKBLUE}...{bcolors.ENDC}')
            serviceOutput.append(f'Scanning ports and services for {ip}\n')
            for x in range(15, 450+1):
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
        outputFunction(list_to_string(serviceOutput), domain)


def initAsnDB():
    print(f'{bcolors.WARNING}[+] Checking if ASN Database already exists...{bcolors.ENDC}')

    if os.path.exists(asnDbPath):
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

    return None

 
def asnLookup(domain):
    asnOutput = []
    try:
        response = dns.resolver.resolve(domain, 'A')
        for ips in response:
            asn = asndb.lookup(str(ips))
            asnOutput.append(f'Origin AS: {asn[0]}, BGP Prefix {asn[1]}\n')
            if outputBool:
                outputFunction(list_to_string(asnOutput), domain)
            
            return f'{bcolors.OKGREEN}{bcolors.BOLD}Origin AS: {asn[0]}, BGP Prefix {asn[1]}{bcolors.ENDC}\n'
    except dns.resolver.NoResolverConfiguration:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')
    
    
    return None

    
def reverseAsnLookup(asn):
    print(f'\n{bcolors.WARNING}[+] Reverse ASN Lookup for {"".join(asn)}...{bcolors.ENDC}')
    output = []
    
    for x in asn:
        response = asndb.get_as_prefixes(x)
        for u in response:
            print(f'{bcolors.OKGREEN}{bcolors.BOLD}{u}{bcolors.ENDC}')
            output.append(u)
            output.append('\n')
    
    if outputBool:
        outputFunction(list_to_string(output), '\n'.join(asn))
    
    return '\n'


def outputFunction(function, domain):

    if os.path.exists('elixir_results.txt'):
        f = open('elixir_results.txt', 'a')
        f.write(f'Results for: {domain}\n\n#----------------#\n' + function + '#----------------#\n\n')
        f.close()
    else:
        f = open('elixir_results.txt', 'w+')
        f.write(f'Results for: {domain}\n\n#----------------#\n' + function + '#----------------#\n\n')
        f.close()

#----------------- End of Functions of Elixir -----------------#


#----------------- Check for updates -----------------#

def checkForUpdates(): 
    try:
        response = requests.get('https://api.github.com/repos/B0lg0r0v/Elixir/releases/latest')
    except requests.exceptions.ConnectionError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}No internet connection.{bcolors.ENDC}')
        exit()    
    
    latestRelease = json.loads(response.text)

    if 'tag_name' in latestRelease:
        latestVersion = latestRelease['tag_name'].lower()

        match = re.search(r'v\d+\.\d+', latestVersion) #Extract only the version number
        if match:
            latestVersion = match.group(0)

        if latestVersion.startswith('v') and CURRENT_VERSION.startswith('v'):
            if latestVersion > CURRENT_VERSION:
                print(f'{bcolors.UNDERLINE}A new version ({latestVersion}) is available. Update with "-up".{bcolors.ENDC}')
                return True
            elif latestVersion == CURRENT_VERSION:
                pass
                return False
            elif latestVersion < CURRENT_VERSION:
                pass
                return False          

#----------------- Main -----------------#

if __name__ == '__main__':

    print("\n")
    print(r"""

    _________      _     
   / ____/ (_)  __(_)____
  / __/ / / / |/_/ / ___/
 / /___/ / />  </ / /    
/_____/_/_/_/|_/_/_/ v0.6    
                             

    Author: B0lg0r0v
    https://root.security
    """)
    print("\n")

    #----------------- Sanitazation Variables -----------------#

    domainSanitazation = re.compile('^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
    ipSanitazation = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    #----------------- Process Variables & Global Variables -----------------#

    outputBool = False
    CURRENT_VERSION = 'v0.6'
    #Get the current directory of the script and append the asn_db.txt file to it. This way, you can use elixir as an alias and it will still work.
    scriptDir = os.path.dirname(os.path.realpath(__file__))
    asnDbPath = os.path.join(scriptDir, '../lists/asn_db.txt')

    #----------------- Argument Parsing -----------------#  
    
    parser = ArgumentParser()
    
    parser.add_argument('-v', '--version', action='version', version='v0.6')
    parser.add_argument('-d', '--domain', help='Target Domain to search for.')
    parser.add_argument('-l', '--list', help='File with a list of domains to search for.', nargs='+')
    parser.add_argument('-a', '--all', help='Find all DNS Records.', action='store_true')
    parser.add_argument('-r', '--record', help='Search for a specific DNS Record. You can also search for multiple records.', nargs='+')
    parser.add_argument('-asn-db', '--asn-build', help='Downloades and creates a Database of ASNs in order to use the ASN Lookup function offline.', action='store_true')
    parser.add_argument('-asn', '--asn', help='Shows you the origin ASN and the BGP prefix of your target. Requires the ASN Database first.', action='store_true')
    parser.add_argument('-rasn', '--rasn', help='Reverse ASN Lookup. Shows you the BGP prefixes using an ASN. Requires the ASN Database first.', nargs='+')
    parser.add_argument('-z', '--zone-transfer', help='Attempts a zone transfer attack.', action='store_true')
    parser.add_argument('-i', '--ip-address', help='Reverse DNS Lookup. You can also put multiple IP addresses.', nargs='+')
    parser.add_argument('-sd', '--subdomains', help='Subdomain brute force using a provided Wordlist. Use this only if you cannot use the "-sdo" argument.', action='store_true')
    parser.add_argument('-sdo', '--subdomains-online', help='Subdomain enumeration which uses free online services. Works very fast.', action='store_true')
    parser.add_argument('-m', '--map', help='Attack surface mapping.', action='store_true')
    parser.add_argument('-s', '--scanning', help='NMAP integration for port scanning & service detection. Works from port 15 up to 450. It needs NMAP to be installed on your system.', action='store_true')
    parser.add_argument('-o', '--output', help='Save results in current directory.', action='store_true')
    parser.add_argument('-up', '--update', help='Update Elixir. This will overwrite all your changes, so be careful.', action='store_true')

    parser.epilog = 'Example: python3 dns.py -d root.security -r TXT A AAAA -z'

    args = parser.parse_args()

    #checking for updates
    checkForUpdates()

    try:
        
        if args.output:         #New output Argument. This will be improved over time and it is currently in testing phase.
               outputBool = True 
        
        #----------------- Arguments where DOMAIN is requried -----------------#
        
        if args.domain is not None:
            
            if args.all:
                if domainSanitazation.search(args.domain):
                    print(f'\n{bcolors.WARNING}[+] Finding all DNS Records...{bcolors.ENDC}')
                    if outputBool:
                        outputFunction(list_to_string(dnsEnumeration.findAllDnsRecords(args.domain)), args.domain)
                    else:
                        dnsEnumeration.findAllDnsRecords(args.domain)             
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
            elif args.domain is None and args.all:
                parser.error('-d / --domain is required.')
            

            if args.record:
                if domainSanitazation.search(args.domain):
                    print(f'\n{bcolors.WARNING}[+] Finding {" ".join(args.record)} Records...{bcolors.ENDC}')
                    if outputBool:
                        outputFunction(list_to_string(dnsEnumeration.findSpecificRecord(args.domain, args.record)), args.domain)
                    else:
                        dnsEnumeration.findSpecificRecord(args.domain, args.record)
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
            elif args.domain is None and args.record is not None:
                parser.error('-d / --domain is required.')
            

            if args.zone_transfer:
                print(f'\n{bcolors.WARNING}[+] Trying Zone Transfer...{bcolors.ENDC}')
                if domainSanitazation.search(args.domain):
                    print(zoneTransfer(args.domain))
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
            elif args.zone_transfer and args.domain is None:
                parser.error('-d / --domain is required.')


            #----------------- Function with Threads -----------------#
            
            if args.subdomains:
                print(f'\n{bcolors.WARNING}[+] Subdomain brute force started...{bcolors.ENDC}')
                if domainSanitazation.search(args.domain):
                    try:
                        if outputBool:
                            outputFunction(list_to_string(bruteForceSubdomains.subdomainEnumeration(args.domain)), args.domain)

                        else:
                            bruteForceSubdomains.subdomainEnumeration(args.domain)

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

            #----------------- Function with Threads -----------------#

            if args.subdomains_online:
                print(f'\n{bcolors.WARNING}[+] Subdomain enumeration started for {args.domain}...{bcolors.ENDC}')
                try:
                    if outputBool: 
                        outputFunction(list_to_string(onlineSubdomains.main(args.domain)), args.domain)
                    else:
                        onlineSubdomains.main(args.domain)

                except KeyboardInterrupt:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')
            
            elif args.subdomains_online and args.domain is None:
                parser.error('-d / --domain is required.')

            #---------------------------------------------------------# 

            if args.map:
                if domainSanitazation.search(args.domain):
                    print(mapDnsRecords(args.domain))
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
            elif args.map and args.domain is None:
                parser.error('-d / --domain is required.')


            #----------------- Function with Threads -----------------#

            if args.scanning:
                print(f'\n{bcolors.WARNING}[+] Scanning ports and services...{bcolors.ENDC}')
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

            if args.asn:
                print(f'\n{bcolors.WARNING}[+] ASN Lookup...{bcolors.ENDC}')
                if os.path.exists(asnDbPath): 
                    asndb = pyasn.pyasn(asnDbPath) #Initializing the Database for ASN lookup.
                    if domainSanitazation.search(args.domain):
                        print(asnLookup(args.domain))
                    else:
                        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
                else:
                    print(f'{bcolors.WARNING}{bcolors.BOLD}Database could not be initialized.{bcolors.ENDC}')
                    asnAnswer = input(f'{bcolors.WARNING}{bcolors.BOLD}ASN Database seems to not exist. Do you want to build it? [y] or [n]: {bcolors.ENDC}')
                    if asnAnswer == 'y'.lower():
                        initAsnDB()
                        asndb = pyasn.pyasn(asnDbPath) #Initializing the Database for ASN lookup.
                        print(asnLookup(args.domain))
                    elif asnAnswer == 'n'.lower():
                        print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                        exit()
            elif args.asn and args.domain is None:
                parser.error('-d / --domain is required.')
               
        
        #----------------- Arguments where DOMAIN or LIST is NOT requried -----------------#

        if args.ip_address and args.domain is None:
            print(f'\n{bcolors.WARNING}[+] DNS Reverse Lookup...{bcolors.ENDC}')
            if outputBool:
                outputFunction(list_to_string(dnsEnumeration.reverseLookup(args.ip_address)), ''.join(args.ip_address))
            else:
                dnsEnumeration.reverseLookup(args.ip_address)

        if args.rasn:
            if os.path.exists(asnDbPath): 
                asndb = pyasn.pyasn(asnDbPath) #Initializing the Database for rASN lookup.
                print(reverseAsnLookup(args.rasn))
            else:
                print(f'{bcolors.WARNING}{bcolors.BOLD}Database could not be initialized.{bcolors.ENDC}')
                rasnAnswer = input(f'{bcolors.WARNING}{bcolors.BOLD}ASN Database seems to not exist. Do you want to build it? [y] or [n]: {bcolors.ENDC}')
                if rasnAnswer == 'y'.lower():
                    initAsnDB()
                    asndb = pyasn.pyasn(asnDbPath) #Initializing the Database for rASN lookup.
                    print(reverseAsnLookup(args.rasn))
                elif rasnAnswer == 'n'.lower():
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                    exit()

        if args.asn_build:
            print(initAsnDB())

        
        if args.update:
            print(f'{bcolors.WARNING}[+] Checking for updates...{bcolors.ENDC}')
            
            if checkForUpdates(): # If CheckForUpdates returns True, then there is a new version available.
                choice = input(f'Are you sure you want to update? This will overwrite all your changes. [y] or [n]: ')
                if choice == 'y'.lower():
                    print(f'{bcolors.WARNING}[+] Updating Elixir...{bcolors.ENDC}')
                    origin = os.getcwd()
                    os.chdir(os.path.dirname(os.path.realpath(__file__)))
                    os.system('git pull')
                    os.chdir(origin)
                    print(f'{bcolors.OKGREEN}{bcolors.BOLD}Update complete.{bcolors.ENDC}')
                elif choice == 'n'.lower():
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                    exit()
                else:
                    print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input.{bcolors.ENDC}')
            else:
                print(f'{bcolors.OKGREEN}{bcolors.BOLD}Elixir is up to date.{bcolors.ENDC}')
       
       #----------------- Arguments where LIST is requried -----------------#
            
        if args.list is not None:
        
            if args.all:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            print(f'\n{bcolors.WARNING}[+] Finding all DNS Record for {line.strip()}...{bcolors.ENDC}')
                            if outputBool:
                                outputFunction(list_to_string(dnsEnumeration.findAllDnsRecords(line.strip())), str(line.strip()))
                            else:
                                dnsEnumeration.findAllDnsRecords(line.strip())
                        else:
                            pass
            
            if args.record:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            print(f'\n{bcolors.WARNING}[+] Finding {" ".join(args.record)} Records for {line.strip()}...{bcolors.ENDC}')
                            if outputBool:
                                outputFunction(list_to_string(dnsEnumeration.findSpecificRecord(line.strip(), args.record)), str(line.strip()))
                            else:
                                dnsEnumeration.findSpecificRecord(line.strip(), args.record)
                        else:
                            pass

            if args.zone_transfer:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            print(f'\n{bcolors.WARNING}[+] Zone Transfer for {line.strip()}...{bcolors.ENDC}')
                            print(zoneTransfer(line.strip()))
                        else:
                            pass
                        
            if args.map:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            mapDnsRecords(line.strip())
                        else:
                            pass

            if args.scanning:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            print(f'\n{bcolors.WARNING}[+] Scanning ports and services for {line.strip()}...{bcolors.ENDC}')
                            serviceDetection(line.strip())
                        else:
                            pass
            
            if args.asn:              
                if os.path.exists(asnDbPath):
                    asndb = pyasn.pyasn(asnDbPath)
                    with open(args.list[0], 'r') as f:
                        for line in f:
                            if line.strip():
                                print(f'\n{bcolors.WARNING}[+] ASN Lookup for {line.strip()}...{bcolors.ENDC}')
                                print(asnLookup(line.strip()))
                            else:
                                pass
                else:
                    print(f'{bcolors.WARNING}{bcolors.BOLD}Database could not be initialized.{bcolors.ENDC}')
                    asnAnswer = input(f'{bcolors.WARNING}{bcolors.BOLD}ASN Database seems to not exist. Do you want to build it? [y] or [n]: {bcolors.ENDC}')
                    if asnAnswer == 'y'.lower():
                        initAsnDB()
                        asndb = pyasn.pyasn(asnDbPath)
                        with open(args.list[0], 'r') as f:
                            for line in f:
                                if line.strip():
                                    print(f'\n{bcolors.WARNING}[+] ASN Lookup for {line.strip()}...{bcolors.ENDC}')
                                    print(asnLookup(line.strip()))
                                else:
                                    pass
                    elif asnAnswer == 'n'.lower():
                        print(f'{bcolors.FAIL}{bcolors.BOLD}Canceled.{bcolors.ENDC}')
                        exit()
                    
            
            if args.subdomains:
                with open(args.list[0], 'r') as f:
                    for line in f:
                        if line.strip():
                            print(f'\n{bcolors.WARNING}[+] Subdomain enumeration started for {line.strip()}...{bcolors.ENDC}')
                            if outputBool:
                                outputFunction(list_to_string(bruteForceSubdomains.subdomainEnumeration(line.strip())), str(line.strip()))
                            else:
                                bruteForceSubdomains.subdomainEnumeration(line.strip())
                        else:
                            pass

            if args.subdomains_online:
                with open(args.list[0], 'r') as f:
                    try:
                        for line in f:
                            if line.strip():
                                print(f'\n{bcolors.WARNING}[+] Subdomain enumeration started for {line.strip()}...{bcolors.ENDC}')
                                if outputBool:
                                    outputFunction(list_to_string(onlineSubdomains.main(line.strip())), str(line.strip()))
                                    time.sleep(5)
                                else:
                                    onlineSubdomains.main(line.strip())
                                    time.sleep(5) #Throttling the requests to avoid getting blocked by the services.
                            else:
                                pass
                    except KeyboardInterrupt:
                        print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')

    except ValueError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Please enter a valid value.{bcolors.ENDC}')
    
    except dns.exception.SyntaxError:
        print(f'{bcolors.FAIL}{bcolors.BOLD}Invalid input detected.{bcolors.ENDC}')
