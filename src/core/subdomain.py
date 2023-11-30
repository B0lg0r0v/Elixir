from bs4 import BeautifulSoup
import requests
from random import randint
import re
import dns.resolver
import dns.zone
import dns.reversename
import os
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

#----------------- "Online" Subdomain Enumeration -----------------#

class onlineSubdomains:

    def suipEnumeration(domain):

        def randBoundary():
            start = 10**(29-1)
            end = (10**29)-1
            return str(randint(start, end))

        hosts = []

        url = 'https://suip.biz/?act=subfinder'
        boundary = randBoundary()
        headers = {

            'Host': 'suip.biz',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Content-Type': f'multipart/form-data; boundary=---------------------------{boundary}',
            'Content-Length': '237'

        }

        body = f'-----------------------------{boundary}\n' + 'Content-Disposition: form-data; name="url"\n\n' + f'{domain}\n' + f'-----------------------------{boundary}\n' + 'Content-Disposition: form-data; name="Submit1"\n\n' + 'Submit'

        soup = BeautifulSoup(requests.post(url, headers=headers, data=body).content, 'html.parser')
        for content in soup.find('pre'):
            hosts.append(content)
        
        return hosts


    def crtSh(domain):
        
        hosts = []

        url = f'https://crt.sh/?q={domain}'
        soup = BeautifulSoup(requests.get(url).content, 'html.parser')
        matches = soup.find_all(string=re.compile(f'{domain}'))
        
        for match in matches:
            hosts.append(match)
        
        return hosts

    def main(domain):

        duplicates = []
        
        subdomains = onlineSubdomains.suipEnumeration(domain) + onlineSubdomains.crtSh(domain)
        for subds in subdomains:
            if subds not in duplicates:
                duplicates.append(subds)
                print(bcolors.OKGREEN + bcolors.BOLD + subds + bcolors.ENDC)
                return subds

#---------------------------------------------------------# 

#----------------- Brute Force Subdomain Enumeration -----------------#

class bruteForceSubdomains:

    def subdomainEnumeration(targetDomain):
        print(f'\n{bcolors.WARNING}[+] Subdomain brute force started...{bcolors.ENDC}')
        list = []
        newList = []

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
                            print(f'{bcolors.OKGREEN}{bcolors.BOLD}{subdomains.lower()}.{targetDomain}{bcolors.ENDC}')

                        else:
                            pass
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.name.EmptyLabel):
                pass
            except KeyboardInterrupt:
                print(f'{bcolors.FAIL}{bcolors.BOLD}\nEnumeration canceled.{bcolors.ENDC}')
                executor.shutdown()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            try:
                executor.map(enumeration, subDomains)
            except KeyboardInterrupt:
                executor.shutdown()
        
        return newList

#---------------------------------------------------------# 

