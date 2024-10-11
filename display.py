import fix_colors
from terminal import running_on_PowerShell
import base64
import datetime
import os

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
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    DARK_YELLOW_BOLD = '\033[33m33'
    
    # Grey highlight versions
    GREEN_GREY_HIGHLIGHT = "\033[100;92m"
    RED_GREY_HIGHLIGHT = "\033[100;1;31m"
    YELLOW_GREY_HIGHLIGHT = "\033[100;93m"
    BLUE_GREY_HIGHLIGHT = "\033[100;94m"
    CYAN_GREY_HIGHLIGHT = "\033[100;96m"
    MAGENTA_GREY_HIGHLIGHT = "\033[100;95m"

    # Reverse colors (color highlight with white text)
    GREEN_REVERSE = "\033[42;97m"
    RED_REVERSE = "\033[41;97m"
    YELLOW_REVERSE = "\033[40;97m" if running_on_PowerShell() else "\033[6;43;97m" # "\033[103;97m"# "\033[43;97m"
    BLUE_REVERSE = "\033[104;97m"  # "\033[44;97m"
    CYAN_REVERSE = "\033[46;97m"
    MAGENTA_REVERSE = "\033[45;97m"

    REVERSE_NEWLINE = "" if running_on_PowerShell() else "\033[F"

    def __init__(self, display=False, backend=True):
        self.display = display
        self.userlogs = {
            'OperatingSystem': RED,
            'Client': BLUE,
            'RelyingParty': GREEN,
            'YubiKey': YELLOW,
            'YubiKey Factory' : DARK_YELLOW_BOLD,
            'Debugger_Override': CYAN
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
    
    @staticmethod
    def clear_display():
        print(f'{Colors.CLEAR}', end='')



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
class CYAN:
    @staticmethod
    def post():
        print(Colors.CYAN, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.CYAN, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.CYAN}{prefix}{Colors.CYAN_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.CYAN}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.CYAN_REVERSE}{s}{Colors.CLEAR}')
class MAGENTA:
    @staticmethod
    def post():
        print(Colors.MAGENTA, end='')
    @staticmethod
    def print(*args, **kwargs):
        print(Colors.MAGENTA, end='\r')
        print(*args, **kwargs)
        print(Colors.CLEAR, end='\r')
    @staticmethod
    def print_backend(prefix: str, header: str, s: str, end='\n'):
        global backend_display
        backend_display(f'\r{Colors.MAGENTA}{prefix}{Colors.MAGENTA_GREY_HIGHLIGHT}{header}{Colors.CLEAR}{Colors.MAGENTA}{s}{Colors.CLEAR}', end=end)
    @staticmethod
    def err(s: str):
        print(f'{Colors.MAGENTA_REVERSE}{s}{Colors.CLEAR}')




class Logger:
    LOG_FILE: str = 'visual/log'
    @staticmethod
    def log(message: str):
        if not os.path.exists(Logger.LOG_FILE):
            open(Logger.LOG_FILE, 'w')
        with open(Logger.LOG_FILE, 'a') as log:
            log.write(f'{Colors.CYAN_GREY_HIGHLIGHT} [{datetime.datetime.now()}] {Colors.CLEAR}  {message}\n\n')


class Logo:
    LOGO_FILE: str = 'visual/logo.cutom'

    @staticmethod
    def read_logo_file() -> str:
        with open(Logo.LOGO_FILE, 'rb') as f:
            return base64.b64decode(f.read()).decode('utf-8')

    @staticmethod
    def display_logo():
        logo = 'FIDO2 POC'
        try:
            logo = Logo.read_logo_file()
        except FileNotFoundError:
            Logger.log("*Logo missing*")
        except Exception:
            Logger.log("An error occurred while loading logo")
        print(logo)

    @staticmethod
    def update_logo(new_logo: str) -> None:
        with open(Logo.LOGO_FILE, 'wb') as f:
            f.write(base64.b64encode(new_logo.encode('utf-8')))
        Logger.log("Logo updated successfully")

class Language:
    display: bool = True
    LETTER_HEIGHT: int = 6
    ALPHABET_FILE: str = 'visual/alphabet.custom'
    LETTERS: dict = {
        key: base64.b64decode(value.encode()).decode() 
        for (key, value) 
        in [
            (v.split(':', 1)) 
            for v 
            in open(ALPHABET_FILE, 'r').readlines() 
            if v != ""
        ]
    }
    @staticmethod
    def to_alphabet(message: str, size: int) -> str:
        overflow = ""
        rows = [""] * Language.LETTER_HEIGHT
        for ch in message.lower():
            if ch in Language.LETTERS:
                letter = Language.LETTERS[ch].split('\n')
                if len(rows[0]) > size - 1 - Language.LETTER_HEIGHT:
                    overflow += "\n".join(rows)
                    rows = [""] * Language.LETTER_HEIGHT
                rows = Language.fix_padding([row + letter[i] for i, row in enumerate(rows)])  
        return overflow + "\n".join(rows)

    @staticmethod
    def fix_padding(rows: list) -> list:
        max_len = max(len(row) for row in rows)
        return [row + " " * (max_len - len(row)) for row in rows]
    
    @staticmethod
    def terminal_size() -> int:
        return os.get_terminal_size()[0]
    
    @staticmethod
    def print_alphabet(message: str) -> None:
        if Language.display:
            print(Language.to_alphabet(message, Language.terminal_size()))

    @staticmethod
    def set_display(value: bool) -> None:
        Language.display = value
