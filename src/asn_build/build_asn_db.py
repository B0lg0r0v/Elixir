import os

def buildASNdb():
    scriptDir = os.path.dirname(os.path.realpath(__file__))
    # Save the original working directory
    origDir = os.getcwd()
    # Change the current working directory to scriptDir
    os.chdir(scriptDir)

    try:
        os.system('python3 pyasn_util_download.py --latest')
        os.system('python3 pyasn_util_convert.py --single rib* asn_db.txt')
        os.system(f'mv asn_db.txt {os.path.join(scriptDir, "../../lists/")}')
        os.system('rm rib*')
    except KeyboardInterrupt:
        print('Building ASN Database canceled.')

    # Change the current working directory back to the original directory
    os.chdir(origDir)