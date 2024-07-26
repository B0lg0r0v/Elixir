from argparse import ArgumentParser

def parse_args():

    CURRENT_VERSION = 'v1.0.0'

    # Initialize parser
    parser = ArgumentParser(description='Elixir')

    # Version info
    parser.add_argument('-v', '--version',
                        help='Version of Elixir', version=f'Elixir {CURRENT_VERSION}', action='version')

    # Add arguments for domain specific search
    parser.add_argument('-d', '--domain', type=str, 
                        help='Target Domain to search for.')
    parser.add_argument('-l', '--list', type=str, 
                        help='List of domains to search for.')
    
    # Resolver arguments
    parser.add_argument('-ns', '--nameserver',
                        help='Use a custom DNS resolver. Can be used with various combinations incl. subdomain bruteforce and DNS record enumeration.', nargs='+')
    
    # Add arguments for dns specific search
    parser.add_argument('-a', '--all',
                        help='All DNS records for the domain.', action='store_true')  
    parser.add_argument('-r', '--records', type=str,
                        help='Search specific DNS records for the domain.', nargs='+')
    parser.add_argument('-asn',
                        help='ASN information for the domain.', action='store_true')
    parser.add_argument('-rdns',
                        help='Reverse DNS Lookup. Give an IP address.')
    
    # Add arguments for subdomain specific search
    parser.add_argument('-sd', '--subdomain',
                        help='Subdomains of the domain.', action='store_true')
    parser.add_argument('-sb', '--subdomain-bruteforce',
                        help='Subdomain bruteforce.', action='store_true')
    parser.add_argument('-m', '--map',
                        help='Attack surface mapping', action='store_true')
    
    # Zone transfer
    parser.add_argument('-z', '--zone-transfer', 
                        help='Attempt a zone transfer.', action='store_true')
    
    # NMAP integration
    parser.add_argument('-s', '--scan',
                        help='NMAP integration. Add custom queries like the following: elixir-dns -d [DOMAIN] -s " -T4 -sC -sV". You NEED to put a whitespace before your first NMAP argument !', nargs='+', type=str, metavar=('OPTIONS'))
    
    # Other arguments
    parser.add_argument('-q', '--quiet',
                        help='Quiet mode. Disables banner.', action='store_true')
    
    parser.epilog = 'Example: elixir-dns -d [DOMAIN] -r TXT A AAAA -s "-T4 -sC -sV" -ns 1.1.1.1' 

    return parser.parse_args()
    