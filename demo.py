# from util import YubiKey, is_signed, RelyingParty
from util import OperatingSystem, RunContext, UserFacingConnection, ConnectionAction, Client, changes_made, cursor, edit_classes_pre_intialization, debug_mode, end_reinstating
from util import set_readline, start_compiler
from typing import Dict, List, Optional
import time
import os
import sys
from arg import Parser
from display import COLOR_CODES, Colors, Logo, Language
from terminal import running_on_shell

just_logged_out: bool = False
just_logged_in: bool = True

class Demo:
    def __init__(self, context: RunContext):
        self.browsers: List[str] = []
        self.OS: OperatingSystem = OperatingSystem(context)
        self.ykIDs: List[str] = []
        self.connections: Dict[str, UserFacingConnection] = {}
        self.visited_websites: List[str] = []
        set_readline([])
        start_compiler()

    def _display_inventory(self):

        if changes_made():
            print("\n  * WARNING: This state has unsaved changes *")

        print("\nINVENTORY:")
        print(f'\tYubiKeys          ({len(self.ykIDs)}) {self.ykIDs}')
        print(f'\tBrowsers          ({len(self.browsers)}) {self.browsers}')
        print(f'\tVisited Websites: ({len(self.visited_websites)}) {self.visited_websites}')
        print(f'\tOpen Connections: ({len(self.connections)}) {self.connections}')
        print('')

    def _webselect(self):
        if len(self.visited_websites) == 0 and len(self.connections) == 0:
            return None
        return self._choose(
            'Where would you like to go?',
            self.visited_websites + ['new website'],
            '  Enter selection > '
        )

    def _choose(self, prefix:str, options:List[str], postfix:str) -> str:
        while True:
            print(prefix)
            for i, option in enumerate(options):
                print(f'\t{i+1}: {option}')
            set_readline(options)
            inp = input(postfix).lower()
            try:
                option_index = int(inp)
                if option_index <= 0 or option_index > len(options):
                    print(f"Invalid option {option_index} not in bounds [1,{len(options)}]")
                    continue
                return options[option_index-1]
            except ValueError as ve:
                for option in options:
                    if option.lower().startswith(inp):
                        return option
                print(f"No matching option found for '{inp}'")
            
            


    def run(self):
        try:
            Logo.display_logo()
            while True:
                self._display_inventory()
                action = self._choose(
                    'Choose an action:',
                    # removed 'show yubikeys' from list (below) - it's redundant
                    ['add yubikey', 'install new browser', 'connect to website', 'save state', 'exit'],
                    '  Enter the number of your choice > '
                )
                if action == 'add yubikey':
                    self.add_yubiKey()
                    continue
                if action == 'show yubikeys':
                    self.show_yubikeys()
                    continue
                if action == 'install new browser':
                    self.install_new_browser()
                    continue
                elif action == 'connect to website':
                    self.connect_to_website()
                    continue
                elif action == 'save state':
                    self.save_state()
                    continue
                elif action == 'exit' and changes_made():
                    self.possible_save_state()
                break
        except KeyboardInterrupt:
            print(f'\n>> {COLOR_CODES.WARN}WARNING: User has inturrupted the program{COLOR_CODES.RESET}')
            if changes_made():
                self.possible_save_state()
        print('Exiting...')

    def possible_save_state(self):
        try:
            print(f'>> {COLOR_CODES.WARN}WARNING: This state has unsaved changes!{COLOR_CODES.RESET}')
            set_readline(['yes', 'no'])
            if input('Do you want to save the current state to a file? (Y/n) > ').lower() in ['y', 'yes']:
                self.save_state()
        except KeyboardInterrupt:
            pass

    def save_state(self):
        try:
            from util import Tracker
            for i in range(20):
                print(f'Collecting data {cursor[i%len(cursor)]}', end='\r')
                time.sleep(0.1)
            RPs: List[str] = [rp.__str__() for rp in Tracker]
            RPs_str = ''
            for rp in RPs:
                RPs_str += f'<RelyingParty>{rp}</RelyingParty>\n'

            while True:
                set_readline(['default.dump'])
                name = input('Enter filedump name: ')
                file = f'{name}.dump' if not name.endswith('.dump') else name
                if os.path.exists(file):
                    set_readline(['yes', 'no'])
                    if input(f'File({file}) already exists, override with current state (Y/n)? ').lower() in ['y', 'yes']:
                        break
                else:
                    break
            self.write_state_to_file(file, RPs_str)
            global state_saved
            state_saved = True
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(1)
        except KeyboardInterrupt:
            print(f'\n>> {COLOR_CODES.WARN}WARNING: User has inturrupted program while saving state. State may not have saved correctly.{COLOR_CODES.RESET}')
    
    def write_state_to_file(self, file: str, relying_partys_string: str):
        with open(file, 'w') as f:
            f.write(f'browsers: {self.browsers}\nyubiKeys: {self.OS.YKs_to_string()}\nvisited_websites: {self.visited_websites}\nconnections: {self.connections}\n')
            f.write(f'{relying_partys_string}')
        print(f'State saved to {file}')


    def install_new_browser(self):
        try:
            set_readline(['Chrome.exe', 'Edge.exe', 'Firefox.exe', 'Opera.exe', 'Safari.exe', 'Brave.exe', 'TorBrowser.exe'])
            browser = input("Enter browser name to install: ")
            self.OS.boot_client(client_name=browser)
            if browser not in self.browsers:
                print(f"Browser '{browser}' installed successfully")
            self.browsers.append(browser)
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(0.2)
        except KeyboardInterrupt as ki:
            print('Browser Installation Failed')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(0.2)

    def add_yubiKey(self):
        try:
            ykID: str = self.OS.new_YubiKey()
            self.ykIDs.append(ykID)
            print(f'You now have {len(self.ykIDs)} yubikeys paired to this device.')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(0.2)
        except KeyboardInterrupt as ki:
            print('YubiKey Creation Failed')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(0.2)
    
    def show_yubikeys(self):
        if len(self.ykIDs) == 0:
            print("You don't have any yubikeys paired to this device")
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(0.2)
            return
        print('Your YubiKey IDs:')
        for i, ykID in enumerate(self.ykIDs):
            print(f'\t{i+1}: {ykID}')
        print('>> RETURNING TO MAIN MENU...\n')
        time.sleep(0.4)

    def connect_to_website(self):
        try:
            if len(self.browsers) == 0:
                print("You don't have any browsers installed, you need a browser to connect to a website")
                print('>> RETURNING TO MAIN MENU...\n')
                time.sleep(1)
                return
            browser = self._choose(
                'Which browser would you like to use?',
                self.browsers,
                '  Enter the number of your choice > '
            )
            client: Client = self.OS.boot_client(client_name=browser)
            Language.print_alphabet(client.name)
            website_name: str = self._webselect()
            if not website_name or website_name == 'new website':
                set_readline(['login.microsoftonline.com', 'attacker.vm', 'wpi.edu', 'accounts.google.com', 'workday.com'])
                website_name = input("Where would you like to connect to: ")
            Portal: UserFacingConnection = self.OS.connect_to_internet(browser, website_name)
            self.connections[f'{client.name}.connect({website_name})'] = Portal
            if website_name not in self.visited_websites: self.visited_websites.append(website_name)
            print('Established connection successfully!')
            ALL_CONECTIONACTIONS: List[ConnectionAction] = [
                # ConnectionAction.Close_Connection, # this is already taken care of
                ConnectionAction.CreateNewAccount,
                ConnectionAction.Login,
                ConnectionAction.Logout,
                ConnectionAction.Update_MFA,
                ConnectionAction.Update_Password,
                ConnectionAction.Show_Account_Tables,
                ConnectionAction.View_Account_Info
            ]
            Language.print_alphabet(website_name)
            while True:
                action: str = self.get_action_from_portal(Portal)
                if action == ConnectionAction.Close_Connection.name:
                    if f'{client.name}.connect({website_name})' in self.connections.keys():
                        del self.connections[f'{client.name}.connect({website_name})']
                    break
                for possible_action in ALL_CONECTIONACTIONS:
                    if action == possible_action.name:
                        if Portal.execute(possible_action):
                            print('\n <<< ACTION COMPLETED >>>\n')
                        else:
                            print('\n <<< ACTION UNSUCCESSFUL >>>\n')
                        break
            print(f'Closing connection to {website_name}...')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(1)
        except KeyboardInterrupt as ki:
            print('\n <<< USER ABANDONED SESSION >>>\n')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(1)
        
        
    def get_action_from_portal(self, portal: UserFacingConnection) -> str:
        global just_logged_out
        global just_logged_in
        actions = [action.name for action in portal.available_actions(portal.connection.client, portal.connection.website)]
        action_header = f'Welcome to {portal.connection.website.name}! What action would you like to run?'
        if portal.is_logged_in():
            if just_logged_in:
                Language.print_alphabet(portal.connection.session_token.for_account)
                just_logged_in = False
            action_header = f'\nWhat action would you like to run:'
            just_logged_out = True
        elif just_logged_out:
            Language.print_alphabet(portal.connection.website.name)
            just_logged_out = False
            just_logged_in = True
        else:
            just_logged_in = True
        return self._choose(
            action_header,
            actions,
            '  Enter the number of your choice > '
        )
    
    def update_backend_settings(self, display: bool):
        self.OS.update_backend_settings(display)
    
    @staticmethod
    def generate_from_dump(filename: str) -> 'Demo':
        from util import RelyingParty, YubiKey
        if not os.path.exists(filename):
            raise FileNotFoundError(f'No such file: {filename}')
        with open(filename, 'r') as f:
            data = f.read()
        datas = data.split('\n')
        blanks: List[str] = ['', ' ', '\t']
        browsers:         List[str] = [b[1:-1] for b in datas[0].split(': [')[1][:-1].split(', ') if b not in blanks]
        yk_strings:       List[str] = [Demo.yk_trim(y) for y in datas[1].split(': [')[1][:-1].split('</YubiKey>') if 'YubiKey' in y]
        visited_websites: List[str] = [v[1:-1] for v in datas[2].split(': [')[1][:-1].split(', ') if v[1:-1] not in blanks]
        d: Demo = Demo(RunContext.AUTO_DETECT)
        d.browsers = browsers
        d.ykIDs = d.OS.digest_YubiKey_strings(yk_strings)
        d.visited_websites = visited_websites
        rps_tmp: List[RelyingParty] = []
        for RP_string in datas[4:]:
            if RP_string in blanks:
                continue
            rps_tmp.append(RelyingParty.from_string(RP_string))
        print(f"\n>> Restored {len(rps_tmp)} Relying Parties...")
        for rp in rps_tmp:
            rp.display_table(offset='\t')
        
        set_readline(['yes', 'no'])
        if input(f'{Colors.CLEAR}>> {Colors.CYAN}Continue? (Y/n) > {Colors.MAGENTA}').lower() in ['y', 'yes']:
            print(Colors.CLEAR + '\n'*25)
            global state_saved
            state_saved = True
            return d
        print(Colors.CLEAR)
        exit(1)
    
    @staticmethod
    def yk_trim(yk_string: str) -> str:
        tmp = yk_string[
            yk_string.index('<YubiKey>') : 
        ] + '</YubiKey>'
        tmp = tmp.replace('\\\'', "'").replace('\\"', '"')
        return tmp



def main(
        session: Optional[Demo], 
        context: Optional[RunContext], 
        _display_crypto_backend: bool, 
        _debug_mode: bool, 
        _debug_challenge: bool,
        _debug_yubikey: bool,
        _fancy_display_location: bool):
    global debug_mode
    debug_mode = _debug_mode
    if _debug_mode and session:
        print(f'>> {COLOR_CODES.CLIENT_LOG}YUBIKEYS:{COLOR_CODES.RESET}')
        for YK_name, YK in session.OS.YubiKeys.items():
            secret = f'{YK}'.split('device_secret=')[1].split('</YubiKey>')[0]
            print(f' {COLOR_CODES.CLIENT_LOG}     {YK_name}, {secret}{COLOR_CODES.RESET}')
        from util import Tracker, YubiKey
        print(f'>> {COLOR_CODES.CLIENT_LOG}RELYING PARTIES:{COLOR_CODES.RESET}')
        for website in Tracker:
            print(f' {COLOR_CODES.CLIENT_LOG}     {website.name}{COLOR_CODES.RESET}')
            for name, account in website.accounts.items():
                yks = 'account.mfa=None'
                if account.mfa_type == 'FIDO-2':
                    pub = f'{YubiKey.public_key_to_bytes(account.public_key)}'
                    yks = f'account.mfa.public_key={pub}'
                elif account.mfa_type == 'OTP':
                    yks = f'account.mfa.YubiKey.ID={account.public_key}'
                elif account.mfa_type == 'Auth App':
                    yks = f'account.mfa.Authenticator.secrete_key={account.public_key}'

                print(f'\t {COLOR_CODES.CLIENT_LOG}      {name}, {account.password_hash}{COLOR_CODES.RESET}')
                print(f'\t {COLOR_CODES.CLIENT_LOG}      {account.salt}{COLOR_CODES.RESET}')
                print(f'\t {COLOR_CODES.CLIENT_LOG}      {yks}{COLOR_CODES.RESET}\n')
    if _debug_mode:
        print(f'>> {COLOR_CODES.CLIENT_LOG}SETTINGS: debug flags will be displayed{COLOR_CODES.RESET}')
    if _display_crypto_backend:
        print(f'>> {COLOR_CODES.CLIENT_LOG}SETTINGS: cryptographic backend will be displayed{COLOR_CODES.RESET}')
    global edit_classes_pre_intialization
    if _debug_challenge:
        print(f'>> {COLOR_CODES.CLIENT_LOG}SETTINGS: you will be able to edit the values of the challenge before it is created{COLOR_CODES.RESET}')
        edit_classes_pre_intialization['Challenge'] = True
    if _debug_yubikey:
        print(f'>> {COLOR_CODES.CLIENT_LOG}SETTINGS: you will be able to edit the values of each yubikey before it is created{COLOR_CODES.RESET}')
        edit_classes_pre_intialization['YubiKey'] = True
    if _debug_mode:
        print(f'\n>> {COLOR_CODES.CLIENT_LOG_HIGHLIGHT}--debug: {COLOR_CODES.RESET}{COLOR_CODES.CLIENT_LOG} running on {running_on_shell()}{COLOR_CODES.RESET}')

    if not session:
        if not context:
            context = RunContext.AUTO_DETECT
        session = Demo(context)
    end_reinstating()
    session.update_backend_settings(_display_crypto_backend)
    if not _fancy_display_location:
        Language.set_display(False)
    session.run()


def generate_session_from_file(filename: Optional[str]) -> Optional[Demo]:
    if not filename:
        return None
    global reinstating
    reinstating = True
    d = Demo.generate_from_dump(filename)
    return d
    

if __name__ == "__main__":
    args = Parser(sys.argv[1:]).parse(legal_lengths=[1, 2, 3, 4, 5, 6])
    filename: Optional[str] = args['--launch-from-save']
    main(
        generate_session_from_file(filename), 
        RunContext.AUTO_DETECT, 
        args['-display_crypto_backend'], 
        args['-debug_mode'], 
        args['-debug_challenge'],
        args['-debug_yubikey'],
        args['-fancy_display_location'])
    
