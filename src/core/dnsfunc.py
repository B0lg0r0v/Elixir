import dns.resolver
import dns.zone
import dns.reversename
from colorama import init as coloramaInit
from colorama import Fore

coloramaInit(autoreset=True)

#----------------- Record Enumeration -----------------#

class dnsEnumeration:

    def findAllDnsRecords(domain):
        dnsRecordTypes = ['A', 'AAAA', 'NS', 'CNAME', 'TXT', 'SOA', 'PTR', 'MX', 'SRV']
        server = []
        serverOutput = []

        try:
            for dnsRecords in dnsRecordTypes:
                try:
                    resolve = dns.resolver.resolve(domain, dnsRecords)
                    for answers in resolve:
                        server.append(f'{Fore.GREEN}{dnsRecords}: ' + answers.to_text() + Fore.RESET + '\n')
                        serverOutput.append(f'{dnsRecords}: {answers.to_text()}\n')
                except dns.resolver.NoAnswer:
                    server.append(f'{Fore.RED}{dnsRecords}: Record not existing{Fore.RESET}\n')
        except dns.resolver.NXDOMAIN:
            print(f'{Fore.RED}{domain} does not exist.{Fore.RESET}\n')
        except (dns.resolver.NoResolverConfiguration, dns.resolver.LifetimeTimeout):
            print(f'{Fore.RED}No NS found or no internet connection.{Fore.RESET}')

        print(Fore.GREEN + ''.join(server) + Fore.RESET)
        
        return serverOutput


    def findSpecificRecord(domain, record):
        response = []
        responseOutput = []
        
        try:
            for recordType in record:
                try:
                    resolve = dns.resolver.resolve(domain, recordType)
                    for answers in resolve:
                        response.append(f'{Fore.GREEN}{recordType} Record: {answers.to_text()}{Fore.RESET}\n')
                        responseOutput.append(f'{recordType} Record: {answers.to_text()}\n')
                except dns.resolver.NoAnswer:
                    response.append(f'{Fore.RED}{recordType} Record not existing.{Fore.RESET}\n')
                    responseOutput.append(f'{recordType} Record not existing.\n')

        except dns.resolver.NXDOMAIN:
            print(f'{Fore.RED}{domain} does not existing.{Fore.RESET}')
        except dns.rdatatype.UnknownRdatatype:
            print(f'{Fore.RED}Error in your record statement.{Fore.RESET}')
        except dns.resolver.NoResolverConfiguration:
            print(f'{Fore.RED}No NS found or no internet connection.{Fore.RESET}')

        
        print(Fore.GREEN + ''.join(response) + Fore.RESET)
        
        return responseOutput


    def reverseLookup(ipAddress):
        dnsNames = []
        dnsNamesOutput = []
        
        try:
            for ips in ipAddress:
                names = dns.reversename.from_address(ips)
                dnsNames.append(f'{Fore.GREEN}Reverse Lookup: {str(dns.resolver.resolve(names, "PTR")[0])}{Fore.RESET}\n')
                dnsNamesOutput.append(f'Reverse DNS Lookup: {str(dns.resolver.resolve(names, "PTR")[0])}\n')
        except dns.resolver.NXDOMAIN:
            print(f'{Fore.RED}{names} does not existing.{Fore.RESET}')
            dnsNamesOutput.append(f'{names} does not existing.\n')

        
        print(''.join(dnsNames))

        return dnsNamesOutput

#---------------------------------------------------------# 



