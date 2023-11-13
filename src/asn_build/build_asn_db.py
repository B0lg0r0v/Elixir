import os

def buildASNdb():
        try:
                os.system('python3 ./asn_build/pyasn_util_download.py --latest')
                os.system('python3 ./asn_build/pyasn_util_convert.py --single rib* asn_db.txt')
                os.system('mv asn_db.txt ../lists/')
                os.system('rm rib*')
        except KeyboardInterrupt:
               print('Building ASN Database canceled.')