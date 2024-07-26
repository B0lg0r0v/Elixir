from src.core.colors import Color
import concurrent.futures
import os
import json
import requests
import re

# Number of threads to use for concurrent processing
NUM_THREADS = int(os.getenv("NUM_THREADS", 40))

class Threads:
    def __init__(self, num_threads=NUM_THREADS):
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads)
    
    def submit(self, func, *args, **kwargs):
        return self.executor.submit(func, *args, **kwargs)

    def shutdown(self):
        self.executor.shutdown(wait=True)

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

class Update:
    def check_version():
        CURRENT_VERSION = 'v1.0.0'

        try:
            response = requests.get('https://api.github.com/repos/B0lg0r0v/Elixir/releases/latest')
        except requests.exceptions.ConnectionError:
            print(Color.red('Error: No internet connection.'))
            exit()    
        
        latestRelease = json.loads(response.text)

        if 'tag_name' in latestRelease:
            latestVersion = latestRelease['tag_name'].lower()

            match = re.search(r'v\d+\.\d+', latestVersion) #Extract only the version number
            if match:
                latestVersion = match.group(0)

            if latestVersion.startswith('v') and CURRENT_VERSION.startswith('v'):
                if latestVersion > CURRENT_VERSION:
                    print(Color.yellow(f'New version available: {latestVersion}'))
                    return True
                elif latestVersion == CURRENT_VERSION:
                    pass
                    return False
                elif latestVersion < CURRENT_VERSION:
                    pass
                    return False          