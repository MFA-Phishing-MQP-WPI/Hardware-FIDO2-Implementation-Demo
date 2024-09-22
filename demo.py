# from util import YubiKey, is_signed, RelyingParty
from util import UserInterface, RunContext, UserFacingConnection, ConnectionAction
from typing import Dict, List, Optional
import time
import os
import sys
import random

class Demo:
    def __init__(self, context: RunContext):
        self.browsers: List[str] = []
        self.ui: UserInterface = UserInterface(context)
        self.ykIDs: List[str] = []
        self.connections: Dict[str, UserFacingConnection] = {}
        self.visited_websites: List[str] = []

    def _display_inventory(self):
        print("\nINVENTORY:")
        print(f'\tBrowsers          ({len(self.browsers)}) {self.browsers}')
        print(f'\tYubiKeys          ({len(self.ykIDs)}) {self.ykIDs}')
        print(f'\tVisited Websites: ({len(self.visited_websites)}) {self.visited_websites}')
        print(f'\tOpen Connections: ({len(self.connections)}) {self.connections}')
        print('')

    def _webselect(self):
        if len(self.visited_websites) == 0:
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
        while True:
            self._display_inventory()
            action = self._choose(
                'Choose an action:',
                ['add yubikey', 'show yubikeys', 'connect to website', 'install new browser', 'save state', 'exit'],
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
            break
        print('Exiting...')

    def save_state(self):
        from util import Tracker
        print('Collecting data', end='\r')
        time.sleep(0.29)
        print('Collecting data.', end='\r')
        time.sleep(0.17)
        print('Collecting data..', end='\r')
        time.sleep(0.51)
        print('Collecting data...', end='\r')
        time.sleep(0.17)
        RPs: List[str] = [rp.__str__() for rp in Tracker]
        RPs_str = ''
        for rp in RPs:
            RPs_str += f'<RelyingParty>{rp}</RelyingParty>\n'

        while True:
            name = input('Enter filedump name: ')
            file = f'{name}.dump' if not name.endswith('.dump') else name
            if os.path.exists(file):
                if input(f'File({file}) already exists, override with current state (Y/n)? ').lower() in ['y', 'yes']:
                    break
            else:
                break
        self.write_state_to_file(file, RPs_str)
        print('>> RETURNING TO MAIN MENU...\n')
        time.sleep(1)
        return
    
    def write_state_to_file(self, file: str, relying_partys_string: str):
        with open(file, 'w') as f:
            f.write(f'browsers: {self.browsers}\nyubiKeys: {self.ui.YKs_to_string()}\nvisited_websites: {self.visited_websites}\nconnections: {self.connections}\n')
            f.write(f'{relying_partys_string}')
        print(f'State saved to {file}')


    def install_new_browser(self):
        try:
            # if len(self.browsers) == 0: 
            #     print("You don't have any browsers installed")
            browser = input("Enter browser name to install: ")
            self.ui.boot_client(client_name=browser)
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
            ykID: str = self.ui.new_YubiKey()
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
            self.ui.boot_client(client_name=browser)
            website_name: str = self._webselect()
            if not website_name or website_name == 'new website':
                website_name = input("Where would you like to connect to: ")
            Portal: UserFacingConnection = self.ui.connect_to_internet(browser, website_name)
            if website_name not in self.visited_websites: self.visited_websites.append(website_name)
            print('Established connection successfully!')
            ALL_CONECTIONACTIONS: List[ConnectionAction] = [
                # ConnectionAction.Close_Connection, # this is already taken care of
                ConnectionAction.CreateNewAccount,
                ConnectionAction.Login,
                ConnectionAction.Logout,
                ConnectionAction.Update_MFA,
                ConnectionAction.Update_Password,
                ConnectionAction.Show_Account_Tables
            ]
            while True:
                action: str = self.get_action_from_portal(Portal)
                if action == ConnectionAction.Close_Connection.name:
                    break
                for possible_action in ALL_CONECTIONACTIONS:
                    if action == possible_action.name:
                        if Portal.execute(possible_action):
                            print('\n <<< ACTION COMPLETED >>>\n')
                        else:
                            print('\n <<< ACTION UNSUCCESSFUL DUE TO python.exceptions.KeyboardInterrupt >>>\n')
                        break
            print(f'Closing connection to {website_name}...')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(1)
        except KeyboardInterrupt as ki:
            print('\n <<< USER ABANDONED SESSION >>>\n')
            print('>> RETURNING TO MAIN MENU...\n')
            time.sleep(1)
        
        
    def get_action_from_portal(self, portal: UserFacingConnection) -> str:
        actions = [action.name for action in portal.available_actions()]
        action_header = f'Welcome to {portal.connection.website.name}! What action would you like to?'
        if portal.is_logged_in():
            action_header = f'Hello {portal.connection.session_token.for_account}! What action would you like to:'
        return self._choose(
            action_header,
            actions,
            '  Enter the number of your choice > '
        )
    
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
        d.ykIDs = d.ui.digest_YubiKey_strings(yk_strings)
        d.visited_websites = visited_websites
        for RP_string in datas[4:]:
            if RP_string in blanks:
                continue
            RelyingParty.from_string(RP_string)
        if input('Continue? (Y/n) > ').lower() in ['y', 'yes']:
            print('\n'*20)
            return d
        exit(1)
    
    @staticmethod
    def yk_trim(yk_string: str) -> str:
        tmp = yk_string[
            yk_string.index('<YubiKey>') : 
        ] + '</YubiKey>'
        tmp = tmp.replace('\\\'', "'").replace('\\"', '"')
        return tmp



def main(session: Optional[Demo], context: Optional[RunContext]):
    # yk = YubiKey(secret=b'\xad\x1d0\x9d\xaa\xa3\xea\xac\x8axj\x89-h\xabm\xa6-\xa8\xa2\xf8-\x94(\x8b\xed\x9an\x1e\xcb\x1b\xd6')
    # pri, pub = yk._generate_key_pair('Microsoft', 'jdoe@wpi.edu')
    # nonce = os.urandom(8)
    # signature = yk.sign(nonce, pri)
    # if is_signed(nonce, pub, signature):
    #     print('Signature verified')
    # else:
    #     print('Signature not verified')
    # Microsoft = RelyingParty('login.microsoft.com')
    # Microsoft.add_account('Jacob')
    # print(Microsoft.auth_user('Jacob', 'password'))
    # Microsoft.add_account('Mark')
    # Microsoft.add_account('Daniel')
    # Microsoft.add_account('Anna', account_password='password123456')
    # Microsoft.display_table()

    # browser = 'Chome.exe'
    # ui: UserInterface = UserInterface(RunContext.AUTO_DETECT)
    # ykID: str = ui.new_YubiKey()
    # ui.boot_client(client_name=browser)
    # Microsoft_Portal: UserFacingConnection = ui.connect_to_internet(browser, 'login.microsoft.com')
    # Microsoft_Portal.execute(ConnectionAction.CreateNewAccount)

    if not session:
        if not context:
            context = RunContext.AUTO_DETECT
        session = Demo(context)
    session.run()


def generate_session_from_file(filename: Optional[str]) -> Optional[Demo]:
    if not filename:
        return None
    return Demo.generate_from_dump(filename)

def check_for_filename() -> Optional[str]:
    if len(sys.argv) == 1:
        return None
    if len(sys.argv) != 3 or sys.argv[1] != '--launch-from-save' or not sys.argv[2].endswith('.dump'):
        print(f'USAGE: python3 demo.py')
        print(f'USAGE: python3 demo.py --launch-from-save <SAVE_FILENAME>.dump')
        exit(1)
    if not os.path.exists(sys.argv[2]):
        print(f'Could not find file "{sys.argv[2]}"')
    return sys.argv[2]
    

if __name__ == "__main__":
    filename: Optional[str] = check_for_filename()
    main(generate_session_from_file(filename), RunContext.AUTO_DETECT)
    
