import fix_colors

class VOID:
    @staticmethod
    def post():
        pass
    @staticmethod
    def print(*args, **kwargs):
        pass
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        pass
    @staticmethod
    def err(*args, **kwargs):
        pass

backend_display = print

class Colors:
    CLEAR = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[1;31m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    DARK_YELLOW_BOLD = '\033[33m33'
    
    # Grey highlight versions
    GREEN_GREY_HIGHLIGHT = "\033[100;92m"
    RED_GREY_HIGHLIGHT = "\033[100;1;31m"
    YELLOW_GREY_HIGHLIGHT = "\033[100;93m"
    BLUE_GREY_HIGHLIGHT = "\033[100;94m"

    # Reverse colors (color highlight with white text)
    GREEN_REVERSE = "\033[42;97m"
    RED_REVERSE = "\033[41;97m"
    YELLOW_REVERSE = "\033[43;97m"
    BLUE_REVERSE = "\033[44;97m"

    def __init__(self, display=False, backend=True):
        self.display = display
        self.userlogs = {
            'OperatingSystem': RED,
            'Client': BLUE,
            'RelyingParty': GREEN,
            'YubiKey': YELLOW,
            'YubiKey Factory' : DARK_YELLOW_BOLD
        }
        if not backend:
            global backend_display
            backend_display = VOID.print
    def log(self, user):
        if not self.display:
            return VOID
        return self.userlogs[user]

    def clear(self):
        if self.display:
            print(Colors.CLEAR, end='')

    def set_backend_display(self, display: bool):
        global backend_display
        backend_display = print if display else VOID.print



class COLOR_CODES:
    RESET: str = Colors.CLEAR
    OK: str = Colors.GREEN
    CLIENT_LOG: str = Colors.BLUE
    CLIENT_LOG_HIGHLIGHT: str = Colors.BLUE_REVERSE
    ERROR: str = Colors.RED
    ERROR_HEADER: str = Colors.RED_REVERSE
    WARN: str = Colors.YELLOW_REVERSE

    @staticmethod
    def err(header: str, message: str):
        print(f'\n\t{COLOR_CODES.ERROR_HEADER}{header.replace(" ", "-").upper()}{COLOR_CODES.RESET}{COLOR_CODES.ERROR}{message}{COLOR_CODES.RESET}\n')

class RED:
    @staticmethod
    def post():
        print(Colors.RED, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.RED, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.RED}{prefix}{Colors.RED_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.RED}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.RED_REVERSE}{s}{Colors.CLEAR}')
class GREEN:
    @staticmethod
    def post():
        print(Colors.GREEN, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.GREEN, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.GREEN}{prefix}{Colors.GREEN_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.GREEN}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.GREEN_REVERSE}{s}{Colors.CLEAR}')
class YELLOW:
    @staticmethod
    def post():
        print(Colors.YELLOW, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.YELLOW, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.YELLOW}{prefix}{Colors.YELLOW_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.YELLOW}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.YELLOW_REVERSE}{s}{Colors.CLEAR}')
class DARK_YELLOW_BOLD:
    @staticmethod
    def post():
        print(Colors.DARK_YELLOW_BOLD, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.DARK_YELLOW_BOLD, end='\r')
        print(*args, Colors.CLEAR, **kwargs)
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        pass
class BOLD:
    @staticmethod
    def post():
        print(Colors.BOLD, end='\r')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.BOLD, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.BOLD}{prefix}{header}{s}{Colors.CLEAR}', end=end)
class BLUE:
    @staticmethod
    def post():
        print(Colors.BLUE, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.BLUE, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.BLUE}{prefix}{Colors.BLUE_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.BLUE}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.BLUE_REVERSE}{s}{Colors.CLEAR}')