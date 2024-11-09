from core.colors import Color
from core.settings import Threads
import dns.resolver
from bs4 import BeautifulSoup
import requests
import json
import re
import os
import sys

class SubdomainEnum:

    def __init__(self, domain):
        self.domain = domain
        self.colors = Color()
        self.resolver = dns.resolver.Resolver()

    
    def crtSh(self):   
        hosts = []

        url = f'https://crt.sh/?q={self.domain}'
        soup = BeautifulSoup(requests.get(url).content, 'html.parser')
        matches = soup.find_all(string=re.compile(f'{self.domain}'))
        
        # remove duplicates and values that contains 'crt.sh' or 'Identity' or 'ILIKE'
        for match in matches:
            if match not in hosts and 'crt.sh' not in match and 'Identity' not in match and 'ILIKE' not in match:
                hosts.append(match)
        
        return hosts
    
    def urlScan(self):
        hosts = []

        url = f'https://urlscan.io/api/v1/search/?q={self.domain}'
        soup = BeautifulSoup(requests.get(url).content, 'html.parser')
        data = json.loads(soup.text)

        for item in data['results']:
            if item['page']['domain'] not in hosts:
                hosts.append(item['page']['domain'])

        return hosts
    
    def combine(self):
        print(self.colors.yellow(f'\n[+] Subdomains for {self.domain}:') + '\n')
        
        try:
            hosts = list(set(self.crtSh() + self.urlScan()))
            for host in hosts:
                try:
                    ip = self.resolver.query(host, 'A')
                    print(self.colors.green(f'{host}'))
                except Exception as e:
                    pass
        
        except KeyboardInterrupt:
            pass

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))

    def main(self):
        try:
            with Threads() as threads:
                threads.submit(self.combine)

        except KeyboardInterrupt:
            threads.shutdown()
        
        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))


class SubdomainBruteforce:
    
        def __init__(self, domain):
            self.domain = domain
            self.colors = Color()
            self.resolver = dns.resolver.Resolver()
    
        def bruteforce(self):
            scriptDir = os.path.dirname(os.path.realpath(__file__))
            wordlist = os.path.join(scriptDir, '../list/subdomains.txt')

            print(self.colors.yellow(f'\n[+] Bruteforcing subdomains for {self.domain}:') + '\n')

            try:
                with open(wordlist, 'r') as f:
                    for line in f:
                        subdomain = line.strip() + '.' + self.domain
                        try:
                            ip = self.resolver.query(subdomain, 'A')
                            print(self.colors.green(f'{subdomain}'))
                        except Exception as e:
                            pass
         
            except KeyboardInterrupt:
                sys.exit(0)
                
            except Exception as e:
                print(self.colors.red(f'Error: {type(e).__name__}'))

        def bruteforce_custom_ns(self, nameserver):
            scriptDir = os.path.dirname(os.path.realpath(__file__))
            wordlist = os.path.join(scriptDir, '../list/subdomains.txt')
            self.resolver.nameservers = nameserver

            print(self.colors.yellow(f'\n[+] Bruteforcing subdomains for {self.domain}:') + '\n')

            try:
                with open(wordlist, 'r') as f:
                    for line in f:
                        subdomain = line.strip() + '.' + self.domain
                        try:
                            ip = self.resolver.query(subdomain, 'A')
                            print(self.colors.green(f'{subdomain}'))
                        except Exception as e:
                            pass
         
            except KeyboardInterrupt:
                sys.exit(0)
                
            except Exception as e:
                print(self.colors.red(f'Error: {type(e).__name__}'))

        
        def main(self):
            try:
                with Threads() as threads:
                    threads.submit(self.bruteforce)

            except KeyboardInterrupt:
                threads.shutdown()
            
            except Exception as e:
                print(self.colors.red(f'Error: {type(e).__name__}'))

        def main_ns(self, nameserver):
            try:
                with Threads() as threads:
                    threads.submit(self.bruteforce_custom_ns, nameserver)

            except KeyboardInterrupt:
                threads.shutdown()
            
            except Exception as e:
                print(self.colors.red(f'Error: {type(e).__name__}'))