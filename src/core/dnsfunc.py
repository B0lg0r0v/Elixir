import dns.resolver
import dns.zone
import dns.reversename

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
                        server.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{dnsRecords}: ' + answers.to_text() + bcolors.ENDC + '\n')
                        serverOutput.append(f'{dnsRecords}: {answers.to_text()}\n')
                except dns.resolver.NoAnswer:
                    server.append(f'{bcolors.FAIL}{bcolors.BOLD}{dnsRecords}: Record not existing{bcolors.ENDC}\n')
        except dns.resolver.NXDOMAIN:
            print(f'{bcolors.FAIL}{bcolors.BOLD}{domain} does not exist.{bcolors.ENDC}\n')
        except dns.resolver.NoResolverConfiguration:
            print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')

        print(bcolors.OKGREEN + bcolors.BOLD + ''.join(server) + bcolors.ENDC)
        
        return serverOutput


    def findSpecificRecord(domain, record):
        response = []
        responseOutput = []
        
        try:
            for recordType in record:
                try:
                    resolve = dns.resolver.resolve(domain, recordType)
                    for answers in resolve:
                        response.append(f'{bcolors.OKGREEN}{bcolors.BOLD}{recordType} Record: {answers.to_text()}{bcolors.ENDC}\n')
                        responseOutput.append(f'{recordType} Record: {answers.to_text()}\n')
                except dns.resolver.NoAnswer:
                    response.append(f'{bcolors.FAIL}{bcolors.BOLD}{recordType} Record not existing.{bcolors.ENDC}\n')
                    responseOutput.append(f'{recordType} Record not existing.\n')

        except dns.resolver.NXDOMAIN:
            print(f'{bcolors.FAIL}{bcolors.BOLD}{domain} does not existing.{bcolors.ENDC}')
        except dns.rdatatype.UnknownRdatatype:
            print(f'{bcolors.FAIL}{bcolors.BOLD}Error in your record statement.{bcolors.ENDC}')
        except dns.resolver.NoResolverConfiguration:
            print(f'{bcolors.FAIL}{bcolors.BOLD}No NS found or no internet connection.{bcolors.ENDC}')

        
        print(bcolors.OKGREEN + bcolors.BOLD + ''.join(response) + bcolors.ENDC)
        
        return responseOutput


    def reverseLookup(ipAddress):
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

        
        print(''.join(dnsNames))

        return dnsNamesOutput

#---------------------------------------------------------# 



