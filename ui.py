from enum import Enum
from os import urandom
from util import YubiKey, Client, Challenge, YubiKeyResponse
import getpass
from typing import Optional

class RunContext(Enum):
    AUTO_DETECT = 1
    INTERACTIVE = 2

__KNOWN_WEBSITES__: dict[str, str] = {
    'Microsoft': 'login.microsoft.com',
    'WPI': 'login.microsoft.com/v3/SSO',
    'Google': 'accounts.google.com',
    'Yahoo': 'login.yahoo.com',
    'Facebook': 'www.facebook.com',
    'Twitter': 'twitter.com',
    'GitHub': 'github.com'
}

class UserInterface:
    def __init__ (self, run_context: RunContext):
        self.run_context = run_context
        # self.websites: dict[str, RelyingParty] = {}
        self.clients: dict[str, Client] = {}
        self.YubiKeys = {}

    def new_YubiKey(self) -> str:
        YK = YubiKey(urandom(32))
        self.YubiKeys[YK.ID] = YK
        return YK.ID

    def boot_client(self, client_name='Chome.exe') -> Client:
        if client_name not in self.clients.keys():
            self.clients[client_name] = Client(client_name)
        return self.clients[client_name]

    def get_connection(self, client_name, website):
        if client_name not in self.clients.keys():
            self.clients[client_name] = Client(client_name)
        client = self.clients[client_name]
        return client.connect(website)

    """
    def get_website(self, name) -> RelyingParty:
        url = f'{name.lower()}.com'
        if name in __KNOWN_WEBSITES__.keys():
            url = __KNOWN_WEBSITES__[name]
        if name in self.websites.keys():
            return self.websites[name]
        return self.add_website(name, url)
    def add_website(self, name, url) -> RelyingParty:
        if name in self.websites.keys():
            return self.websites[name]
        website = RelyingParty(url)
        self.websites[name] = website
        return website
"""
    def login(self, web_name) -> bool:
        RP = self.get_website(web_name)
        if RP.number_of_accounts == 0:
            print(f'UserInterface ERR: No accounts found for "{web_name}". Create an account first.')
            return False
        while True:
            username = input(f' ${RP.name}: Enter username > ')
            password = getpass.getpass(prompt=f' ${RP.name}: Enter password > ')
            b_token: Optional[bytes] = RP.grant_session_token_1FA(username, password)
            if not b_token: 
                print(f' ${RP.name}: Username or Password incorrect. Access denied. (1FA Fail)')
                if input(f'UserInterface: Try again? (Y/n) > ').lower() in ['y', 'yes']:
                    continue
                return False
            break
        if RP.requires_2FA(username):
            print(f' ${RP.name}: usr="{username}" requires 2FA...')
            print(f' ${RP.name}: insert and auth using YubiKey for the respective account.')
            if len(self.YubiKeys.keys()) == 0:
                print(f'UserInterface ERR: No YubiKeys found. Add one first.')
                return False
            while True:
                resp = input(f'UserInterface: Enter YubiKey ID or enter "-SHOW YUBIKEY IDs" to view all known YubiKey IDs > ')
                
        print(f'$ {RP.name}: Successfully logged in as "{username}". Access granted')

    def insert_yubikey(self) -> Optional[int]:
        while True:
            resp = input(f'UserInterface: Enter YubiKey ID or enter "-SHOW YUBIKEY IDs" to view all known YubiKey IDs > ')
            if resp.lower() == '-show yubikey ids':
                print('UserInterface: YubiKey IDs:')
                for id, YK in self.YubiKeys.items():
                    print(f'  {id}: {YK}')
                continue
            try:
                id = int(resp)
                if id in self.YubiKeys.keys():
                    print(f'UserInterface: YubiKey({id}) inserted into computer...')
                    return id
            except ValueError:
                if input(f'UserInterface: No such key ("{id}"), try again (Y/n)? ').lower() in ['y', 'yes']:
                    continue
                print(f"UserInterface: You didn't enter a YubiKey in time!")
                return None
    # will always return bytes, may be wrong but will always return bytes (never None)
    def YubiKey_auth(self, ykID: int, challenge: Challenge) -> Optional[YubiKeyResponse]:
        YK: YubiKey = self.YubiKeys[ykID]
        return YK.auth_2FA(challenge)