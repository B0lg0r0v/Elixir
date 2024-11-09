# -*- coding: utf-8 -*-

from core.arguments import parse_args
from core.colors import Color, banner
from core.subdomains import SubdomainEnum, SubdomainBruteforce
from core.dnsfunc import DnsEnum
from core.settings import Update
from core.nmap import Nmap

def main():
    # Initializing
    args = parse_args()
    colors = Color()

    if args.quiet is False:
        banner()
        Update.check_version()
        # Main part 
        if args.domain:
            if args.nameserver is None:
                if args.all:
                    dns = DnsEnum(args.domain)
                    dns.get_all_dns_records()

                if args.records:
                    dns = DnsEnum(args.domain)
                    dns.get_specific_dns_records(args.records)

                if args.subdomain:
                    subd = SubdomainEnum(args.domain)
                    subd.main()
                
                if args.subdomain_bruteforce:
                    subb = SubdomainBruteforce(args.domain)
                    subb.main()
                
                if args.asn:
                    asn = DnsEnum(args.domain)
                    asn.get_asn()

                if args.map:
                    maps = DnsEnum(args.domain)
                    maps.map_attack_surface()

                if args.scan:
                    nmap = Nmap()
                    nmap.custom_scan(args.domain, args.scan)          


            if args.nameserver is not None:
                if args.all:
                    dns = DnsEnum(args.domain)
                    dns.get_all_dns_records_resolver(args.nameserver)
                
                if args.records:
                    dns = DnsEnum(args.domain)
                    dns.get_specific_dns_records_resolver(args.nameserver, args.records)

                if args.subdomain_bruteforce:
                    subb_ns = SubdomainBruteforce(args.domain)
                    subb_ns.main_ns(args.nameserver)

                if args.map:
                    maps = DnsEnum(args.domain)
                    maps.map_attack_surface_ns(args.nameserver)

                if args.scan:
                    nmap = Nmap()
                    nmap.custom_resolver_nmap(args.domain, args.nameserver, args.scan)

            if args.zone_transfer:
                dns = DnsEnum(args.domain)
                dns.zone_transfer()

        if args.rdns is not None:
            if args.nameserver is None:
                dns = DnsEnum(None)
                dns.reverse_dns_lookup(args.rdns)
            
            if args.nameserver is not None:
                dns = DnsEnum(None)
                dns.reverse_dns_lookup_ns(args.rdns, args.nameserver)

        if args.list:
            with open(args.list, 'r') as file:
                f = file.readlines()
            
            if args.nameserver is None:
                if args.all:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_all_dns_records()
                
                if args.records:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_specific_dns_records(args.records)

                if args.subdomain:
                    for domain in f:
                        domain = domain.strip()
                        subd = SubdomainEnum(domain)
                        subd.main()
                
                if args.subdomain_bruteforce:
                    for domain in f:
                        domain = domain.strip()
                        subb = SubdomainBruteforce(domain)
                        subb.main()
                
                if args.asn:
                    for domain in f:
                        domain = domain.strip()
                        asn = DnsEnum(domain)
                        asn.get_asn()
                
                if args.map:
                    for domain in f:
                        domain = domain.strip()
                        maps = DnsEnum(domain)
                        maps.map_attack_surface()

                if args.scan:
                    for domain in f:
                        domain = domain.strip()
                        nmap = Nmap()
                        nmap.custom_scan(domain, args.scan)

            if args.zone_transfer:
                for domain in f:
                    domain = domain.strip()
                    dns = DnsEnum(domain)
                    dns.zone_transfer()
            
            if args.nameserver is not None:
                if args.all:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_all_dns_records_resolver(args.nameserver)
                
                if args.records:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_specific_dns_records_resolver(args.nameserver, args.records)

                if args.subdomain_bruteforce:
                    for domain in f:
                        domain = domain.strip()
                        subb_ns = SubdomainBruteforce(domain)
                        subb_ns.main_ns(args.nameserver)

                if args.map:
                    for domain in f:
                        domain = domain.strip()
                        maps = DnsEnum(domain)
                        maps.map_attack_surface_ns(args.nameserver)

                if args.scan:
                    print(Color.yellow(f'\n[!] Using custom DNS resolver with NMAP: {" ".join(args.nameserver)}'))
                    for domain in f:
                        domain = domain.strip()
                        nmap = Nmap()
                        nmap.custom_resolver_nmap(domain, args.nameserver, args.scan)


    if args.quiet is True:
        Update.check_version()
        # Main part 
        if args.domain:
            if args.nameserver is None:
                if args.all:
                    dns = DnsEnum(args.domain)
                    dns.get_all_dns_records()

                if args.records:
                    dns = DnsEnum(args.domain)
                    dns.get_specific_dns_records(args.records)

                if args.subdomain:
                    subd = SubdomainEnum(args.domain)
                    subd.main()
                
                if args.subdomain_bruteforce:
                    subb = SubdomainBruteforce(args.domain)
                    subb.main()
                
                if args.asn:
                    asn = DnsEnum(args.domain)
                    asn.get_asn()

                if args.map:
                    maps = DnsEnum(args.domain)
                    maps.map_attack_surface()

                if args.scan:
                    nmap = Nmap()
                    nmap.custom_scan(args.domain, args.scan)

            if args.nameserver is not None:
                if args.all:
                    dns = DnsEnum(args.domain)
                    dns.get_all_dns_records_resolver(args.nameserver)
                
                if args.records:
                    dns = DnsEnum(args.domain)
                    dns.get_specific_dns_records_resolver(args.nameserver, args.records)

                if args.subdomain_bruteforce:
                    subb_ns = SubdomainBruteforce(args.domain)
                    subb_ns.main_ns(args.nameserver)

                if args.map:
                    maps = DnsEnum(args.domain)
                    maps.map_attack_surface_ns(args.nameserver)

                if args.scan:
                    nmap = Nmap()
                    nmap.custom_resolver_nmap(args.domain, args.nameserver, args.scan)

            if args.zone_transfer:
                dns = DnsEnum(args.domain)
                dns.zone_transfer()

        if args.rdns is not None:
            if args.nameserver is None:
                dns = DnsEnum(None)
                dns.reverse_dns_lookup(args.rdns)
            
            if args.nameserver is not None:
                dns = DnsEnum(None)
                dns.reverse_dns_lookup_ns(args.rdns, args.nameserver)

        if args.list:
            with open(args.list, 'r') as file:
                f = file.readlines()
            
            if args.nameserver is None:
                if args.all:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_all_dns_records()
                
                if args.records:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_specific_dns_records(args.records)

                if args.subdomain:
                    for domain in f:
                        domain = domain.strip()
                        subd = SubdomainEnum(domain)
                        subd.main()
                
                if args.subdomain_bruteforce:
                    for domain in f:
                        domain = domain.strip()
                        subb = SubdomainBruteforce(domain)
                        subb.main()
                
                if args.asn:
                    for domain in f:
                        domain = domain.strip()
                        asn = DnsEnum(domain)
                        asn.get_asn()
                
                if args.map:
                    for domain in f:
                        domain = domain.strip()
                        maps = DnsEnum(domain)
                        maps.map_attack_surface()

                if args.scan:
                    for domain in f:
                        domain = domain.strip()
                        nmap = Nmap()
                        nmap.custom_scan(domain, args.scan)

            if args.zone_transfer:
                for domain in f:
                    domain = domain.strip()
                    dns = DnsEnum(domain)
                    dns.zone_transfer()
            
            if args.nameserver is not None:
                if args.all:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_all_dns_records_resolver(args.nameserver)
                
                if args.records:
                    for domain in f:
                        domain = domain.strip()
                        dns = DnsEnum(domain)
                        dns.get_specific_dns_records_resolver(args.nameserver, args.records)

                if args.subdomain_bruteforce:
                    for domain in f:
                        domain = domain.strip()
                        subb_ns = SubdomainBruteforce(domain)
                        subb_ns.main_ns(args.nameserver)

                if args.map:
                    for domain in f:
                        domain = domain.strip()
                        maps = DnsEnum(domain)
                        maps.map_attack_surface_ns(args.nameserver)

                if args.scan:
                    print(Color.yellow(f'\n[!] Using custom DNS resolver with NMAP: {" ".join(args.nameserver)}'))
                    for domain in f:
                        domain = domain.strip()
                        nmap = Nmap()
                        nmap.custom_resolver_nmap(domain, args.nameserver, args.scan)

if __name__ == '__main__':
    main()

    
