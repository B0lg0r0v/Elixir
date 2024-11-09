class Color():
    @staticmethod
    def red(str):
        return "\033[91m" + str + "\033[0m"

    @staticmethod
    def green(str):
        return "\033[92m" + str + "\033[0m"

    @staticmethod
    def yellow(str):
        return "\033[93m" + str + "\033[0m"

    @staticmethod
    def blue(str):
        return "\033[94m" + str + "\033[0m"
    

def banner():
    print(r"""

   ______   _____  _________ 
  / __/ /  /  _/ |/_/  _/ _ \
 / _// /___/ /_>  <_/ // , _/
/___/____/___/_/|_/___/_/|_| v1.1.0
    """ + 
    (Color.blue("\n\tAuthor: B0lg0r0v") + Color.blue("\n\thttps://arthurminasyan.com\n")))
