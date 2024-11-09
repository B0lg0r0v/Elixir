from core.colors import Color
import dns.resolver
import dns.reversename
from bs4 import BeautifulSoup
import requests
import json

class DnsEnum:

    def __init__(self, domain):
        if domain is not None:
            self.domain = domain
        
        self.colors = Color()
        self.resolver = dns.resolver.Resolver()

    def get_ip(self) -> str:
        try:
            ip = self.resolver.resolve(self.domain, 'A')
            for rdata in ip:
                return rdata
        except Exception as e:
            return None


    # Get all DNS records for the domain. The OS resolver is used.
    def get_all_dns_records(self):
        dns_records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT']
        results = []

        print(self.colors.yellow(f'\n[+] All DNS records for {self.domain}:') + '\n')
        results.append(f'\nAll DNS records for {self.domain}:\n')

        try:
            for records in dns_records:
                try:
                    resolve = self.resolver.resolve(self.domain, records)
                    for rdata in resolve:
                        print(self.colors.green(f'{records}: {rdata}'))
                        results.append(f'{records}: {rdata}')

                except dns.resolver.NoAnswer:
                    print(self.colors.red(f'No {records} records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))
            
        return results
    
    # Get specific DNS records for the domain. The OS resolver is used.
    def get_specific_dns_records(self, records):
        print(self.colors.yellow(f'\n[+] Specific DNS records for {self.domain}:') + '\n')

        try:
            for record in records:
                try:
                    resolve = self.resolver.resolve(self.domain, record)
                    for rdata in resolve:
                        print(self.colors.green(f'{record}: {rdata}'))

                except dns.resolver.NoAnswer:
                    print(self.colors.red(f'No {record} records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))


    # Reverse DNS lookup with IP address. Using the OS resolver.
    def reverse_dns_lookup(self, ip):
        print(self.colors.yellow(f'\n[+] Reverse DNS Lookup for {ip}:') + '\n')

        try:
            rev_name = dns.reversename.from_address(ip)
            resolve = self.resolver.resolve(rev_name, 'PTR')
            for rdata in resolve:
                print(self.colors.green(f'PTR: {rdata}'))

        except dns.resolver.NoAnswer:
            print(self.colors.red(f'No PTR records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))


    def map_attack_surface(self):
        print(self.colors.yellow(f'\n[+] Mapping the attack surface for {self.domain}:') + '\n')

        indent = '    '  
        dns_records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT']

        print(self.colors.yellow(f'┌──———————— {self.domain}————————'))
        try:
            for records in dns_records:
                try:
                    resolve = self.resolver.resolve(self.domain, records)
                    for rdata in resolve:
                        subdomain = rdata.to_text()
                        #print(self.colors.green(f'{indent}| {records}: {subdomain}'))
                        if records == 'A' or records == 'AAAA':
                            
                            print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'{self.colors.blue(self.geolocation(subdomain))}')
                        
                        if records == 'MX':
                            mx = subdomain.split(' ')[1]
                            mxIP = self.resolver.resolve(mx, 'A')
                            for ip in mxIP:
                                print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'IP: {ip}')

                        if records == 'NS':
                            nsIP = self.resolver.resolve(subdomain, 'A')
                            for ip in nsIP:
                                print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'IP: {ip}')
                                
                except dns.resolver.NoAnswer:
                    pass
        
        except KeyboardInterrupt:
            pass

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))
    
    def geolocation(self, subdomain):
        
        response = requests.get(f'http://ip-api.com/json/{subdomain}') #Using http instead of https because of the free API. You may want to change that.
        data = response.json()
    
        if response.status_code == 200:
            city = data.get('city')
            region = data.get('regionName')
            country = data.get('country')
            isp = data.get('isp')
            asn = data.get('as')

            res = f'City: {city}, Region: {region}, Country: {country}, ISP: {isp}, ASN: {asn}'
            return res
        else:
            print(f'Error: {data.get("message")}')
        


    # Zone transfer.
    def zone_transfer(self):
        print(self.colors.yellow(f'\n[+] Attempting Zone Transfer for {self.domain}:') + '\n')

        try:
            ns = self.resolver.resolve(self.domain, 'NS')
            for rdata in ns:
                ip = self.resolver.resolve(rdata.to_text(), 'A')
                for ips in ip:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ips), self.domain))
                        for host in zone:
                            print(self.colors.green(f'{host}'))

                    except dns.zone.NoAxfr:
                        print(self.colors.red(f'Zone Transfer failed.'))
        
        except dns.resolver.NoAnswer:
            print(self.colors.red(f'No NS records found.'))
        
        except Exception as e:
            print(self.colors.red(f'Error: Zone Transfer refused.'))

    
    def get_asn(self):
        print(self.colors.yellow(f'\n[+] ASN information for {self.domain}:') + '\n')

        hosts = []

        url = f'https://urlscan.io/api/v1/search/?q={self.domain}'
        soup = BeautifulSoup(requests.get(url).content, 'html.parser')
        data = json.loads(soup.text)

        for item in data['results']:
            if self.domain in item['page']['apexDomain']:
                asn = item['page'].get('asn')
                domain = item['page'].get('domain')
                asn_name = item['page'].get('asnname')
                if asn and asn not in hosts:
                    hosts.append(asn)
                    print(self.colors.green(f'ASN: {asn} - {asn_name} - ({domain})'))
        
        return hosts




    #------------------ Custom DNS resolver ------------------#

    # Get all DNS records for the domain. A custom DNS resolver is used.
    def get_all_dns_records_resolver(self, resolver):
        dns_records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT']
        self.resolver.nameservers = resolver
        
        print(self.colors.yellow(f'\n[+] All DNS records for {self.domain}:') + '\n')

        try:
            for records in dns_records:
                try:
                    resolve = self.resolver.resolve(self.domain, records)
                    for rdata in resolve:
                        print(self.colors.green(f'{records}: {rdata}'))

                except dns.resolver.NoAnswer:
                    print(self.colors.red(f'No {records} records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))

    
    # Get specific DNS records for the domain. A custom DNS resolver is used.
    def get_specific_dns_records_resolver(self, resolver, records):
        self.resolver.nameservers = resolver

        print(self.colors.yellow(f'\n[+] Specific DNS records for {self.domain}:') + '\n')
        
        try:
            for record in records:
                try:
                    resolve = self.resolver.resolve(self.domain, record)
                    for rdata in resolve:
                        print(self.colors.green(f'{record}: {rdata}'))

                except dns.resolver.NoAnswer:
                    print(self.colors.red(f'No {record} records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))

    def reverse_dns_lookup_ns(self, ip, resolver):
        self.resolver.nameservers = resolver

        print(self.colors.yellow(f'\n[+] Reverse DNS Lookup for {ip}:') + '\n')

        try:
            rev_name = dns.reversename.from_address(ip)
            resolve = self.resolver.resolve(rev_name, 'PTR')
            for rdata in resolve:
                print(self.colors.green(f'PTR: {rdata}'))

        except dns.resolver.NoAnswer:
            print(self.colors.red(f'No PTR records found.'))   

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))
    
    def map_attack_surface_ns(self, resolver):
        self.resolver.nameservers = resolver

        print(self.colors.yellow(f'\n[+] Mapping the attack surface for {self.domain}:') + '\n')

        indent = '    '  
        dns_records = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT']

        print(self.colors.yellow(f'┌──———————— {self.domain}————————'))
        try:
            for records in dns_records:
                try:
                    resolve = self.resolver.resolve(self.domain, records)
                    for rdata in resolve:
                        subdomain = rdata.to_text()
                        #print(self.colors.green(f'{indent}| {records}: {subdomain}'))
                        if records == 'A' or records == 'AAAA':
                            
                            print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'{self.colors.blue(self.geolocation(subdomain))}')
                        
                        if records == 'MX':
                            mx = subdomain.split(' ')[1]
                            mxIP = self.resolver.resolve(mx, 'A')
                            for ip in mxIP:
                                print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'IP: {ip}')

                        if records == 'NS':
                            nsIP = self.resolver.resolve(subdomain, 'A')
                            for ip in nsIP:
                                print(self.colors.yellow(f'│ ') + self.colors.green(f'{records}: {subdomain}') + ' -----> ' + f'IP: {ip}')
                                
                except dns.resolver.NoAnswer:
                    pass
        
        except KeyboardInterrupt:
            pass

        except Exception as e:
            print(self.colors.red(f'Error: {type(e).__name__}'))