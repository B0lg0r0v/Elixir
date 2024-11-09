from core.colors import Color
import os


class Nmap:

    def __init__(self) -> None:
        self.colors = Color()

    def custom_scan(self, target, options):
        # Check if NMAP is installed on the OS. Check in the /usr/local/bin/directory or /usr/bin directory or /bin directory
        if not os.path.exists('/usr/local/bin/nmap') and not os.path.exists('/usr/bin/nmap') and not os.path.exists('/bin/nmap'):
            print(self.colors.red('Error: NMAP is not detected on the system.'))
            exit()
        
        print(self.colors.yellow(f'\n[+] Scanning {target}') + '\n')
        scan_options = ''.join(options)
        #print(scan_options)
        os.system(f'nmap {target} {scan_options}')

    def custom_resolver_nmap(self, target, nameserver, options):
        if not os.path.exists('/usr/local/bin/nmap') and not os.path.exists('/usr/bin/nmap') and not os.path.exists('/bin/nmap'):
            print(self.colors.red('Error: NMAP is not detected on the system.'))
            exit()
        
        scan_options = ''.join(options)
        ns = ' '.join(nameserver)
        print(self.colors.yellow(f'\n[+] Scanning {target}') + '\n')
        os.system(f'nmap {target} {scan_options} --dns-servers {ns}')
