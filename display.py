
class VOID:
    @staticmethod
    def post():
        pass
    @staticmethod
    def print(*args, **kwargs):
        pass
    @staticmethod
    def print_backend(header: str, s: str):
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
            'UserInterface': RED,
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
    def print_backend(header: str, s: str):
        global backend_display
        backend_display(f'{Colors.RED_GREY_HIGHLIGHT}{header}{Colors.RED}{s}{Colors.CLEAR}')
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
    def print_backend(header: str, s: str):
        global backend_display
        backend_display(f'{Colors.GREEN_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.GREEN}{s}{Colors.CLEAR}')
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
    def print_backend(header: str, s: str):
        global backend_display
        backend_display(f'{Colors.YELLOW_GREY_HIGHLIGHT}{header}{Colors.YELLOW}{s}{Colors.CLEAR}')
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
    def print_backend(header: str, s: str):
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
    def print_backend(header: str, s: str):
        global backend_display
        backend_display(f'{Colors.BOLD}{header}{s}{Colors.CLEAR}')
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
    def print_backend(header: str, s: str):
        global backend_display
        backend_display(f'{Colors.BLUE_GREY_HIGHLIGHT}{header}{Colors.BLUE}{s}{Colors.CLEAR}')
    @staticmethod
    def err(s: str):
        print(f'{Colors.BLUE_REVERSE}{s}{Colors.CLEAR}')