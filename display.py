class Colors:
    CLEAR = "\033[0m"
    GREEN = "\033[92m"
    RED = "\033[1;31m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    # DARK_YELLOW_BOLD = "\e[0;33m"
    DARK_YELLOW_BOLD = '\033[33m33'

    def __init__(self, display=False):
        self.display = display
        self.userlogs = {
            'UserInterface': BLUE,
            'Client': RED,
            'RelyingParty': GREEN,
            'YubiKey': YELLOW,
            'YubiKey Factory' : DARK_YELLOW_BOLD
        }
    def log(self, user):
        if not self.display:
            return VOID
        return self.userlogs[user]

    def clear(self):
        if self.display:
            print(Colors.CLEAR, end='')

class RED:
    @staticmethod
    def post():
        print(Colors.RED, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.RED, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class GREEN:
    @staticmethod
    def post():
        print(Colors.GREEN, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.GREEN, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class YELLOW:
    @staticmethod
    def post():
        print(Colors.YELLOW, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.YELLOW, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class DARK_YELLOW_BOLD:
    @staticmethod
    def post():
        print(Colors.DARK_YELLOW_BOLD, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.DARK_YELLOW_BOLD, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class BOLD:
    @staticmethod
    def post():
        print(Colors.BOLD, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.BOLD, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class BLUE:
    @staticmethod
    def post():
        print(Colors.BLUE, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.BLUE, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
class VOID:
    @staticmethod
    def post():
        pass
    @staticmethod
    def print(*args, **kwargs):
        pass