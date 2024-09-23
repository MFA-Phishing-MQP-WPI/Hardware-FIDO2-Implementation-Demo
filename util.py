import os
import re
import base64
import hmac
from hashlib import sha256
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature
import time
import datetime
import string
import random
from enum import Enum
from typing import Optional, List, Dict
from display import Colors

state_saved: bool = False
display_backend: bool = True

console: Colors = Colors(display=True, backend=True)
WEBSITES: Dict[str, 'RelyingParty'] = {}

class ConnectionAction(Enum):
    # can always do
    Close_Connection = 0
    Show_Account_Tables = 1

    # can only do when not logged in
    Login = 11
    CreateNewAccount = 12

    # can only do when logged in
    View_Account_Info = 20
    Update_Password = 21
    Update_MFA = 22
    Logout = 23

Tracker: List['RelyingParty'] = []
class Hasher:
    def __init__(self, password: str, salt: Optional[bytes] = None, display: bool = True):
        if salt is None:
            salt = os.urandom(32)
            Hasher.print_backend(display, f'No salt provided ... Generating random salt: {salt.hex()}')
        Hasher.print_backend(display, f'Initializing Hasher object from password="{password}" and salt={salt.hex()}...')
        self.salt = salt
        self.hashed_password = self._hash_password(password, salt)

    def _hash_password(self, password: str, salt: bytes, display=display_backend) -> str:
        Hasher.print_backend(display, f'Using Argon2 to hash password...')
        ph = PasswordHasher()
        return ph.hash(password.encode(), salt=salt)

    def hash_str(self, display=display_backend) -> str:
        Hasher.print_backend(display, f'Generating hash string... (i.e. "[hashed_password]:[salt]")')
        Hasher.print_backend(display, f'Resulting hash: "{self.hashed_password}"')
        return f"{self.hashed_password}:{self.salt.hex()}"
    
    def __str__(self) -> str:
        return self.hash_str()
    def __repr__(self) -> str:
        return self.hash_str()
    
    def __eq__(self, other: 'Hasher') -> bool:
        if not isinstance(other, Hasher):
            return False
        return self.hashed_password == other.hashed_password and self.salt == other.salt

    def is_same_password(self, password: str) -> bool:
        provided_hasher = Hasher(password, salt=bytes.fromhex(self.salt.hex()))
        return provided_hasher == self
    @staticmethod
    def is_correct_password(password: str, hash_string: str) -> bool:
        stored_hasher = Hasher.from_hash_string(hash_string)
        provided_hasher = Hasher(password, salt=bytes.fromhex(stored_hasher.salt.hex()))
        return provided_hasher == stored_hasher

    @staticmethod
    def from_hash_string(hash_string: str, display=display_backend) -> 'Hasher':
        Hasher.print_backend(display, f'Creating Hasher object from hash string: {hash_string}')
        hashed_password, salt = hash_string.split(':')
        salt = bytes.fromhex(salt)
        Hasher.print_backend(display, f'Extracted salt: {salt.hex()}')
        hasher = Hasher("", salt=salt)  
        hasher.hashed_password = hashed_password  
        return hasher
    @staticmethod
    def print_backend(display: bool, message: str) -> None:
        if display:
            print('       ', end='')
            console.log('RelyingParty').print_backend('$RP(g).crypto_backend:', f" {message}")

class YubiKeyResponse:
    signature: bytes
    nonce: bytes
    YubiKeyID: str

class MFARegistrationRequest:
    def __init__(self, RP_ID: str, username: str):
        self.RP_ID: str = RP_ID
        self.username: str = username

class MFARegistrationApproval:
    def __init__(self, public_key: str, YubiKeyID: str):
        self.public_key: str = public_key
        self.YubiKeyID: str = YubiKeyID

class YubiKey:
    def __init__(self, secret:Optional[bytes]=None, ID:Optional[str]=None):
        if not secret:
            secret = YubiKey._gen_secret(print_fun=True)
        if not ID:
            ID = get_rand_id(12)
        self._device_secret: bytes = secret
        self.ID: str = ID
        console.log('YubiKey').print(f'   $YK({self.ID}): initializing for the first time...')
        time.sleep(0.1)
    
    def register_account(self, request: MFARegistrationRequest) -> MFARegistrationApproval:
        _, public_key = self._generate_key_pair(request.RP_ID, request.username)
        return MFARegistrationApproval(public_key, self.ID)

    def _generate_key_pair(self, rp_id, account_info, print_debug=False):
        display = print if print_debug else void
        display(f'   $TK({self.ID}) Generating key pair inside YubiKey...')
        secret_material = self._device_secret + rp_id.encode('utf-8') + account_info.encode('utf-8')
        display(f"       1.     Known: {rp_id=}, {account_info=}, {self._device_secret=}")
        display(f'          Concat to get secret material: {secret_material}\n')
        
        # Use HMAC-SHA256 to derive a key from the secret material
        derived_key = hmac.new(self._device_secret, secret_material, sha256).digest()
        display('        2. Calculate key from secret')

        # Convert derived key to an integer (this will act as a deterministic seed for EC key generation)
        seed = int.from_bytes(derived_key, byteorder='big') % ec.SECP256R1().key_size
        display('        3. Convert derived key into integer to use as seed for EC key generation')

        # Generate the private key deterministically using the derived seed
        private_key = ec.derive_private_key(seed, ec.SECP256R1(), default_backend())
        display('        4. Generate private key using calculated seed deterministically')

        # Derive the public key from the private key
        public_key = private_key.public_key()
        display('        5. Derive public key from private key')

        # Serialize public key for transmission/storage (compressed point format)
        public_key_bytes = public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)

        # display(f"Public Key (Compressed): {public_key_bytes.hex()}")
        # display(f'Private Key {YubiKey._private_key_to_number(private_key)}')
        return (private_key, public_key)
    
    def auth_2FA(self, challenge: 'Challenge') -> Optional[YubiKeyResponse]:
        private_key, _ = self._generate_key_pair(challenge.RP_ID, challenge.username)
        return self._sign(challenge.nonce, private_key)
    def _sign(self, nonce: bytes, private_key) -> YubiKeyResponse:
        """
        Signs the given nonce using the private key and returns the signature.
        """
        signature = private_key.sign(
            nonce,
            ec.ECDSA(hashes.SHA256())  # Using ECDSA with SHA-256
        )
        return YubiKeyResponse(signature, nonce, self.ID)
    
    @staticmethod
    def _private_key_to_number(private_key) -> int:
        return private_key.private_numbers().private_value
    
    @staticmethod
    def from_string(s: str) -> 'YubiKey':
        id_pattern = r"<YubiKey>([A-Za-z0-9]+),"
        secret_pattern = r", b'(.*?)'"
        secret_backup_pattern = r', b"(.*?)"'
        id_match = re.search(id_pattern, s)
        secret_match = re.search(secret_pattern, s)
        secret_backup_match = re.search(secret_backup_pattern, s)
        yk_id = id_match.group(1) if id_match else None
        device_secret_str = eval(f"b'{secret_match.group(1)}'") if secret_match else eval(f'b"{secret_backup_match.group(1)}"') if secret_backup_match else None
        yk = YubiKey(secret=device_secret_str, ID=yk_id)
        return yk
    
    
    @staticmethod
    def _gen_secret(print_fun=False) -> bytes:
        secret = os.urandom(32)
        console.log('YubiKey').print("No secret specified. Generating random secret", end='\r')
        time.sleep(0.3)
        console.log('YubiKey').print("No secret specified. Generating random secret.", end='\r')
        time.sleep(0.21)
        console.log('YubiKey').print("No secret specified. Generating random secret..", end='\r')
        time.sleep(0.28)
        console.log('YubiKey').print("No secret specified. Generating random secret...", end='\r')
        time.sleep(0.47)
        console.log('YubiKey').print(f"No secret specified. Generating random secret   {secret}")
        return secret
    
class Account:
    def __init__(self, name: str, hash: Hasher, pk=None, pk_id: Optional[str] = None):
        self.name: str = name
        self._hasher_object: Hasher = hash
        self.password_hash: str = ''
        self.salt: str          = ''
        self.password_hash, self.salt = self._hasher_object.hash_str().split(':')
        self.public_key = pk
        self.public_key_to_display = pk_id

    def has_same_password(self, password: str) -> bool:
        return Hasher.is_correct_password(
            password, 
            self._hasher_object.hash_str()
        )

    def __str__(self) -> str:
        return f'<Account>Username={self.name}<br-splitter>Password={self.password_hash}:{self.salt}<br-splitter>public_key={self.public_key}<br-splitter>public_key_to_display={self.public_key_to_display}</Account>'

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def from_string(account_string: str) -> 'Account':
        username_pattern = r"Username=(.*?)<br-splitter>"
        password_pattern = r"Password=(.*?)<br-splitter>"
        public_key_pattern = r"public_key=(.*?)<br-splitter>"
        public_key_to_display_pattern = r"<br-splitter>public_key_to_display=(.*?)</Account>"

        # Extract the username, password hash, and public key using regex
        username_match = re.search(username_pattern, account_string)
        password_match = re.search(password_pattern, account_string)
        public_key_match = re.search(public_key_pattern, account_string)
        public_key_to_display_match = re.search(public_key_to_display_pattern, account_string)

        # Get the matches, convert password hash to bytes, handle public key 'None'
        username = username_match.group(1) if username_match else None
        password_hash_str = password_match.group(1) if password_match else None
        public_key = public_key_match.group(1) if public_key_match else None
        public_key_to_display = public_key_to_display_match.group(1) if public_key_to_display_match else None


        # If public_key is the string 'None', convert it to actual None type
        if public_key == 'None':
            public_key = None
        if public_key_to_display == 'None':
            public_key_to_display = None
        if not password_hash_str:
            print('\n\nerr: dumping...')
            print(f'{account_string=}')
            print(f'{password_hash_str=}')
            raise ValueError('Invalid password hash group specified')
        account: Account = Account(username, Hasher.from_hash_string(password_hash_str), pk=public_key, pk_id=public_key_to_display)
        return account
    @staticmethod
    def split(s: str) -> List['Account']:
        l: List[Account] = []
        for account_string in s.split('</Account>'):
            if account_string in ['{}', ' ', '', '\t', ']', '[', '[]']:
                continue
            acc: Account = Account.from_string(account_string + '</Account>')
            l.append(acc)
        return l


class SessionToken:
    def __init__(self, account: str, hours: float, auth_type: str, auth_type_required: str, by_connection: 'Connection', data: bytes = os.urandom(16)):
        self.for_account: str = account
        self.auth_type: str = auth_type
        self.account_requires: str = auth_type_required
        self.nonces = {}
        self.active: bool = True
        self.by_connection: Connection = by_connection

        # hidden
        self._expires_on = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + hours * 3600
        self._data = data
        self._value_string = f'Account={self.for_account},atype={self.auth_type},expires={self._expires_on},nonce={self._data.hex()}'
    
    def __str__(self) -> str:
        return f'<SessionToken>Username={self.for_account},Type={self.auth_type},RequiredType={self.account_requires},Nonces={self.nonces},Active={self.active}</SessionToken>'
    def set_inactive(self) -> None:
        self.active = False
    def is_logged_in(self) -> bool:
        return not self.timmed_out() and self.active and self.auth_type == self.account_requires
    def value(self):
        return hash(self._value_string)
    def reinstate(self, new_hours: float) -> None:
        self._expires_on = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + new_hours * 3600
    def timmed_out(self) -> bool:
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp()) > self._expires_on
    def is_valid(self, account: str, auth_type: str) -> bool:
        if self.timmed_out() or not self.active:
            return False
        value_string = f'Account={account},atype={auth_type},expires={self._expires_on},nonce={self._data.hex()}'
        return hash(value_string) == self.value()  # validate
    def add_nonce(self, nonce: str) -> str:
        n_id = get_rand_id(12)
        self.nonces[n_id] = nonce
        return n_id
    def is_same(self, thash) -> bool:
        return self.value() == thash



class Challenge:
    def __init__(self, RP_ID, username, token_1FA, NonceID, Nonce):
        self.RP_ID = RP_ID
        self.username = username
        self.token_1FA = token_1FA
        self.NonceID = NonceID
        self.nonce = Nonce

class RelyingParty:
    def __init__(self, name: str):
        self.name = name
        self.accounts: Dict[str, Account] = {}
        self._longest_account_length = len('Username')  # used for displaying in table
        self.tokens = {}
        self.INDENT = "     "
        self.classname = 'RelyingParty'
        self.p(f'initializing for the first time...')
        global Tracker
        Tracker.append(self)
        time.sleep(0.2 + 0.05 * len(self.accounts.keys()))

    def __str__(self) -> str:
        accounts: List[Account] = []
        for a_name in self.accounts.keys():
            accounts.append(self.accounts[a_name])
        return f'RelyingParty({self.name})=||STARTER||{accounts}||SEPER||{self._longest_account_length}||ENDER||'

    def p(self, *args, **kwargs):
        s = ''
        for a in args:
            s += str(a)
        end = '\n'
        if 'end' in kwargs.keys():
            end = kwargs['end']
        console.log(self.classname).print(f'{self.INDENT}$RP({self.name}): {a}', end=end)

    def crypto(self, s: str):
        console.log(self.classname).print_backend(f'{self.INDENT}$RP({self.name}): {s}')

    def number_of_accounts(self):
        return len(self.accounts)

    def can_run_secure_account_actions(self, session: Optional[SessionToken]) -> bool:
        if not session or not session.is_valid(session.for_account, session.account_requires):
            self.p(f'No Active Session.')
            self.p(f'You must be logged in to run secure account actions.')
            return False
        return True

    def update_account_password(self, session: Optional[SessionToken]) -> bool:
        try:
            if not self.can_run_secure_account_actions(session):
                return False
            username: str = session.for_account
            self.p(f'Enter Old Password {Colors.CLEAR}', end='')
            old_password: str = getpass.getpass(prompt='')
            self.p(f'Enter New Password {Colors.CLEAR}', end='')
            new_password: str = getpass.getpass(prompt='')
            self.p(f'Confirm new password {Colors.CLEAR}', end='')
            new_password2: str = getpass.getpass(prompt='')
        except KeyboardInterrupt as ki:
            return False
        if not self.update_password(username, old_password, new_password, new_password2):
            self.p('Couldn\'t update password')
            return False
        global state_saved
        state_saved = False
        self.p('Password updated successfully')
        return True

    def view_account_info(self, session: Optional[SessionToken]) -> bool:
        try:
            acc: Account = self.accounts[session.for_account]
            self.p(f'Account Information:')
            self.p(f'\tUsername: {acc.name}')
            self.p(f'\tPassword Hash: {acc.password_hash}')
            self.p(f'\tPublic Key: {acc.public_key}')
            return True
        except KeyboardInterrupt as ki:
            return False

    def update_account_MFA(self, session: Optional[SessionToken]) -> bool:
        try:
            if not session or not session.is_valid(session.for_account, session.account_requires):
                self.p(f'{session.for_account} as been inactive for too long.')
                self.p(f'{session.for_account} has been logged out.')
                return False
            self.p(f'Enter your current password {Colors.CLEAR}', end='')
            password: str = getpass.getpass(prompt='')
            if not self.valid_login(session.for_account, password):
                self.p(f'Incorrect password.')
                return False
            client: Client = session.by_connection.client
            self.p(f'Sending request to Client({client.name})', end='\r')
            time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) .', end='\r')
            time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . .', end='\r')
            time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . . .')
            time.sleep(0.05)
            
            request: MFARegistrationRequest = MFARegistrationRequest(self.name, session.for_account)
            approval: Optional[MFARegistrationApproval] = client.request_registration(request, self, session.by_connection.UI_ptr)

            if not approval:
                self.p('Waiting for approval ', end='\r')
                time.sleep(0.4)
                self.p('Waiting for approval .', end='\r')
                time.sleep(0.4)
                self.p('Waiting for approval . .', end='\r')
                time.sleep(0.4)
                self.p('Waiting for approval . . .')
                time.sleep(0.4)
                self.p('Request timmed out')
                return False
            
            self.p('Waiting for approval ', end='\r')
            time.sleep(0.2)
            self.p('Waiting for approval .', end='\r')
            time.sleep(0.05)
            self.p(f'Recieved approval from Client({client.name})')
            self.accounts[session.for_account].public_key = approval.public_key
            self.accounts[session.for_account].public_key_to_display = f'YK({approval.YubiKeyID})'
            self.p(f'Updated user settings for user="{session.for_account}" to public_key="{approval.public_key}"')
            self.show_table_question()
            global state_saved
            state_saved = False
            return True
        except KeyboardInterrupt as ki:
            return False

    def update_password(self, username: str, old_password: str, new_password: str, new_password2: str) -> bool:
        if username not in self.accounts:
            return False
        if not self.valid_login(username, old_password):
            return False
        if new_password!= new_password2:
            return False
        new_hash = hash(new_password)
        self.accounts[username].password_hash = new_hash
        global state_saved
        state_saved = False
        return True

    def end_session(self, session: SessionToken) -> bool:
        self.tokens.pop(session.value(), None)
        session.set_inactive()
        return True

    def create_new_account(self, connection: 'Connection') -> bool:
        try:
            client_name = connection.client.name
            console.log('Client').print(f'   $Client({client_name}): Requesting new account from RP({self.name})')
            time.sleep(0.1)
            self.p(f'Recieved new account request from Client({client_name})')
            self.p(f'Forwarding new account message and form to Client({client_name})')
            time.sleep(0.1)
            console.log('Client').print(f'   $Client({client_name}): Recieved new account message and form from RP({self.name})')
            console.log('Client').print(f'   $Client({client_name}): Printing new account message and requesting new account form from user...')
            time.sleep(0.2)
            print('')
            time.sleep(0.25)
            console.log('Client').print(f'   $Client({client_name}): WELCOME NEW USER TO {self.name.capitalize()}!')
            console.log('Client').print(f'   $Client({client_name}): Let\'s create a new account!')
            time.sleep(0.1)
            console.log('Client').post()
            username = input(f'   $Client({client_name}): Enter your username > {Colors.CLEAR}')
            console.log('Client').print(f'   $Client({client_name}): Enter your password {Colors.CLEAR}', end='')
            password = getpass.getpass(prompt='')
            console.log('Client').print(f'   $Client({client_name}): Confirm your password {Colors.CLEAR}', end='')
            confirm_password = getpass.getpass(prompt='')
            console.log('Client').print(f'   $Client({client_name}): Passing filled out form to RP({self.name})')
            if password != confirm_password:
                console.clear()
                console.log(self.classname).err(f'{self.INDENT}$RP({self.name})::ERR - Passwords do not match.')
                return False
            console.clear()
            if not self.add_account(username, password):
                return False
            console.log(self.classname).print(f'{self.INDENT}$RP({self.name})::WARNING ACCOUNT {username.upper()} DOES NOT HAVE 2FA CONFIGURED')
            self.p(f'Account {username} created successfully!')
            self.show_table_question()
            return True
        except KeyboardInterrupt as ki:
            return False

    def show_table_question(self):
        console.log(self.classname).post()
        if input(f'{self.INDENT}$RP({self.name}): show table of all users (Y/n)? {Colors.CLEAR}').lower() in ['y', 'yes']:
            console.clear()
            self.display_table()
        console.clear()

    def _add_token(self, account, token):
        if account not in self.tokens.keys():
            raise ValueError(f"Account '{account}' does not exist.")
        self.tokens[account].append(token)

    def add_account(self, account_name: str, account_password: str = 'password') -> bool:
        try:
            if account_name in self.accounts.keys():
                raise ValueError(f"Account '{account_name}' already exists.")
            self.tokens[account_name] = []
            # pHash, salt = Hasher(account_password).hash_str().split(':')
            self.accounts[account_name] = Account(
                account_name,
                Hasher(account_password)
            )
            self._longest_account_length = max(self._longest_account_length, len(account_name))
            return True
        except KeyboardInterrupt as ki:
            return False
    # def update_account_password(self, account_name: str, new_password: str) -> None:
    #     if account_name not in self.accounts.keys():
    #         raise ValueError(f"Account '{account_name}' does not exist.")
    #     self.accounts[account_name].password_hash = hash(new_password)
    def update_account_public_key(self, account_name: str, public_key) -> None:
        if account_name not in self.accounts.keys():
            raise ValueError(f"Account '{account_name}' does not exist.")
        global state_saved
        state_saved = False
        self.accounts[account_name].public_key = public_key
    def display_table(self) -> bool:
        print(f"\nRelying Party '{self.name}' accounts table:")
        dotted_line = '-' * (self._longest_account_length + 2)
        seper = f'|{dotted_line}|---------------------------------------|-----------------------------|----------------|'
        print('_' * len(seper))
        print('| ' + 'Username'.center(self._longest_account_length) + ' | ' + 'Password Hash'.center(37) + ' | ' + 'Password Salt'.center(27) + ' | MFA Public Key |')
        print(seper)
        for account_name, account in self.accounts.items():
            username = account_name.center(self._longest_account_length)
            public_key = '    Exists    ' if account.public_key else '     None     '
            hash, salt = account._hasher_object.hash_str(display=False).split(':')
            print(f'| {username} | {hash[:34]}... | 0x{salt.upper()[:22]}... | {public_key} |')
        print('‾' * len(seper))
        return True
    def _generate_token(self, account: str, hours: float, auth_type: str, required_auth_type: str, by_connection: 'Connection') -> SessionToken:
        new_token = SessionToken(
            account,
            hours,
            auth_type,
            required_auth_type,
            by_connection,
            data=os.urandom(16)
        )
        self._add_token(
            account, 
            new_token
        )
        return new_token
    def prune_tokens(self) -> None:
        for user, tokens in self.tokens.items():
            self.tokens[user] = [
                token for token in tokens if not token.timmed_out()
            ]
    def user_has_access(self, account:str, auth_type:str, spec_token = None) -> bool:
        self.prune_tokens()
        for token in self.tokens[account]:
            # validate token for this user and this action
            if token.is_valid(account, auth_type) and \
                (not spec_token or token.is_same(spec_token)): # will only run if spec_token is not None
                return True
        return False
    def get_token(self, account:str, auth_type:str, spec_token = None):
        self.prune_tokens()
        for token in self.tokens[account]:
            # validate token for this user and this action
            if token.is_valid(account, auth_type) and \
                (not spec_token or token.is_same(spec_token)): # will only run if spec_token is not None
                return token
        return None
    def valid_login(self, username: str, password: str) -> bool:
        if username not in self.accounts.keys():
            console.log(self.classname).print(f' --d $RP({self.name}): Username could not be found! Sending code "HTTP 403" back to Client')
            return False
        console.log(self.classname).print(f'     $RP({self.name}): Hashing password with stored salt to compare against stored hashed password...')
        time.sleep(0.1)
        response: bool = self.accounts[username].has_same_password(password)
        if response:
            console.log(self.classname).print(f' --d $RP({self.name}): Password Hash matches! Sending code "HTTP 200" back to Client')
        else:
            console.log(self.classname).print(f' --d $RP({self.name}): Password Hash does not match! Sending code "HTTP 403" back to Client')
        time.sleep(0.1)
        return response
    def grant_session_token_1FA(self, username: str, password: str, by_connection: 'Connection') -> Optional[SessionToken]:
        console.log(self.classname).print(f'     $RP({self.name}): Recieved Tuple(Username, Password) from Client({self.name})')
        time.sleep(0.1)
        if self.valid_login(username, password):
            # grant user token for 1FA
            # it will time out in 3 minutes (0.05 hours) unless user authenticates with 2FA
            # post-2FA: new token will be granted to user (1 hour exp) assuming this token is still valid
            return self._generate_token(
                username, 
                0.05, 
                '1FA',
                'MFA' if self.accounts[username].public_key else '1FA',
                by_connection
                )
        return None # failed varification (username/password wrong)
    def grant_session_token_MFA(
            self, 
            username: str, 
            session: SessionToken, 
            response: YubiKeyResponse,
            connection: 'Connection'
            ) -> Optional[SessionToken]:
        try:
            if session.timmed_out:
                return None
            if not session.is_valid(username, '1FA'):
                return None
            if is_signed(
                response.nonce,
                self.accounts[session.for_account].public_key,
                response.signature
            ):
                return SessionToken(session.for_account, 1, 'MFA', 'MFA', connection)
        except KeyboardInterrupt as ki:
            pass
        return None # failed MFA verification (YubiKey response not valid)
        
    def request_challenge(self, username: str, token: bytes, ykID: int) -> Challenge:
        TK = self.get_token(username, '1FA', token)
        if not TK:
            raise ValueError('Permission denied - token not found or expired')
        nonce = os.urandom(32)
        console.log(self.classname).print(f'     $RP({self.name}): generating challenge for usr="{username}", YubiKey({ykID})')
        return Challenge(
            self.name,
            username,
            token,
            TK.add_nonce(nonce),
            nonce
        )
    def requires_2FA(self, username: str) -> bool:
        if username not in self.accounts:
            raise ValueError(f'User "{username}" not found')
        return not not self.accounts[username].public_key

    @staticmethod
    def from_string(relying_party_string: str) -> 'RelyingParty':
        rp_dict: dict = RelyingParty.extract(relying_party_string)
        rp = RelyingParty(rp_dict['name'])
        accounts: List[Account] = rp_dict['accounts']
        for account in accounts:
            rp.accounts[account.name] = account
            rp.tokens[account.name] = []
            # print(f'Added account({account.name}) to RP({rp.name})')
        rp._longest_account_length = rp_dict['_longest_account_length']
        rp.display_table()
        global WEBSITES
        WEBSITES[rp.name] = rp
        
        

    @staticmethod
    def extract(s: str) -> dict:
        pattern = r'RelyingParty\((?P<name>.*?)\)=\|\|STARTER\|\|(?P<accounts>.*?)\|\|SEPER\|\|(?P<_longest_account_length>\d+)\|\|ENDER\|\|'
        match = re.search(pattern, s)
        if not match:
            raise ValueError("String format doesn't match the expected pattern.\nstring=" + s)
        # Constructing the dictionary with the parsed values
        return {
            "name": match.group("name"),
            "accounts": Account.split(match.group("accounts")),
            "_longest_account_length": int(match.group("_longest_account_length"))
        }


class Connection:
    def __init__(self, client: 'Client', website: RelyingParty, UI_ptr: 'UserInterface'):
        self.client: Client = client
        self.website: RelyingParty = website
        self.session_token: Optional[SessionToken] = None
        self.UI_ptr: UserInterface = UI_ptr

    def request_yubikey_insert_from_OS(self) -> Optional[int]:
        return self.UI_ptr.insert_yubikey()

    def request_yubikey_auth_from_OS(self, ykID, challenge) -> bytes:
            return self.UI_ptr.YubiKey_auth(ykID, challenge)
    def login(self) -> bool:
        token: SessionToken = self.client._login_user(self)
        if token:
            self.session_token = token
            console.log('Client').print(f'   $Client({self.client.name}): successfully logged in as "{self.session_token.for_account}"')
            return True
        console.log('Client').print(f'   $Client({self.client.name}): failed to login')
        return False
    
    def is_logged_in(self) -> bool:
        return self.session_token and self.session_token.is_logged_in()


class Client:
    def __init__(self, name='Chome.exe'):
        self.name = name
        # self.websites: Dict[str, RelyingParty] = {}
        console.log('Client').print(f'   $Client({self.name}): initializing for the first time...')
        time.sleep(0.25)

    def request_registration(self, request: MFARegistrationRequest, talking_to: RelyingParty, operating_system: 'UserInterface') -> Optional[MFARegistrationApproval]:
        console.log('Client').print(f'   $Client({self.name}): Recieved request for MFA registration for account="{request.username}"')
        if request.RP_ID != talking_to.name:
            console.log('Client').err(f'   $Client({self.name}): ERR: Requested registration for account="{request.username}" by unexpected RP "{request.RP_ID}" DOES NOT MATCH RP ID provided in request.')
            console.log('Client').print(f'   $Client({self.name}): Ignoring request.')
            return None
        console.log('Client').print(f'   $Client({self.name}): Verified that we are communicating with RP({talking_to.name}). This RP ID matches what was provided in the request (i.e. {request.RP_ID}).') 
        time.sleep(0.25)
        console.log('Client').print(f'   $Client({self.name}): Passing request to Operating System.')
        response: Optional[MFARegistrationApproval] = operating_system.approve_mfa_registration_request(request, self)
        if response:
            console.log('Client').print(f'   $Client({self.name}): Received approval from Operating System.')
            console.log('Client').print(f'   $Client({self.name}): Passing approval to RP({talking_to.name}).')
            return response
        console.log('Client').print(f' $Client({self.name}): did not recieve approval yet ... still waiting ')
        time.sleep(0.35)
        return None

    def add_website(self, website: RelyingParty):
        global WEBSITES
        if website.name not in WEBSITES:
            WEBSITES[website.name] = website

    def connect(self, website, UI_ptr) -> Connection:
        global WEBSITES
        console.log('Client').print(f'   $Client({self.name}): attempting to connect to "{website}"')
        if website not in WEBSITES:
            WEBSITES[website] = RelyingParty(website)
            global state_saved
            state_saved = False
        return Connection(self, WEBSITES[website], UI_ptr)
    
    def connected_action(self, connection: Connection, action: ConnectionAction) -> bool:
        if action == ConnectionAction.Login:
            return not not self._login_user(connection)

    def _login_user(self, connection: Connection) -> Optional[SessionToken]:
        try:
            global WEBSITES
            web_name = connection.website.name
            RP = WEBSITES[web_name]
            if RP.number_of_accounts() == 0:
                console.log('Client').err(f'   $Client({self.name})::ERR: No accounts found for "{web_name}". Create an account first.')
                return None
            while True:
                console.log('Client').print(f'   $Client({self.name}): Sending login request to RP({RP.name})')
                console.log(RP.classname).print(f'     $RP({RP.name}): Requesting Tuple(Username, Password) from Client({self.name})')
                console.log('Client').post()
                username = input(f'   $Client({self.name}): Enter username > {Colors.CLEAR}')
                console.log('Client').print(f'   $Client({self.name}): Enter password > {Colors.CLEAR}', end='')
                password = getpass.getpass(prompt='')
                secure_password = '*' * len(password)
                console.log('Client').print(f'   $Client({self.name}): Passing Tuple({username, secure_password}) to RP({RP.name})')
                session_token: Optional[SessionToken] = RP.grant_session_token_1FA(username, password, connection)
                if not session_token: 
                    console.log(RP.classname).print(f'     $RP({RP.name}): Username or Password incorrect. Access denied. (1FA Fail)')
                    console.log('Client').print(f'   $Client({self.name}): Recieved "HTTP 403" (Access denied) from RP({RP.name})')
                    console.log('Client').post()
                    if input(f'   $Client({self.name}): Try again? (Y/n) > {Colors.CLEAR}').lower() in ['y', 'yes']:
                        continue
                    return None
                break
            console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}): Username and password hash match...')
            if RP.requires_2FA(username):
                console.log(RP.classname).print(f'     $RP({RP.name}): usr="{username}" requires 2FA...')
                console.log(RP.classname).print(f'     $RP({RP.name}): insert and auth using YubiKey for the respective account.')
                ykID: Optional[int] = connection.request_yubikey_insert_from_OS()
                if not ykID:
                    console.log(RP.classname).print(f'     $RP({RP.name}): usr="{username}" timmed out')
                    console.log('Client').print(f'   $Client({self.name}): 2FA failed. Access denied.')
                    return None
                challenge: Challenge = RP.request_challenge(username, session_token, ykID) # will print generating challenge
                if challenge.RP_ID != RP.name:
                    console.log('Client').print(f'   $Client({self.name}): failed to varify challenge sender as ({RP.name}). Challenge originating ID does not match communicating sub-domain. ')
                    space = ' ' * len(f'   $Client({self.name}): ')
                    console.log('Client').print(f'{space}... ignoring challenge')
                    console.log(RP.classname).print(f'     $RP({RP.name}): usr="{username}" timmed out')
                    console.log('Client').print(f'   $Client({self.name}): 2FA failed. Access denied.')
                    return None
                console.log('Client').print(f'   $Client({self.name}): verified challenge sender as ({RP.name}). Challenge originating ID matches communicating sub-domain.')
                space = ' ' * len(f'   $Client({self.name}): ')
                console.log('Client').print(f'{space}... passing challenge to operating system for YubiKey authentication')
                response: Optional[bytes] = connection.request_yubikey_auth_from_OS(ykID, challenge)
                if not response:
                    console.log('Client').print(f'RESPONSE FAILED?????????')
                session_token: SessionToken = RP.grant_session_token_MFA(username, session_token, response, connection)
                if not session_token:
                    console.log('Client').print(f'  $Client({self.name}): SIGN IN FAILED!!!!!!!!')
                console.log('Client').print("  $Client({self.name}): SIGN IN SUCCESS!!!!!!!!")
            else:
                console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}): User={username} does not have 2FA configured -> skipping 2FA')
            console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}): User={username} Access Granted!')
        except KeyboardInterrupt as ki:
            return None
        return session_token


def get_rand_id(length: int) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=length))
    
def hash(inp:str)->bytes:
    sha256_instance = sha256()
    sha256_instance.update(inp.encode('utf8'))
    return sha256_instance.digest()

def is_signed(nonce: bytes, public_key, response: bytes) -> bool:
    """
    Verifies that the given response is a valid signature for the nonce, using the public key.
    """
    try:
        # Verify the signature using the public key
        public_key.verify(
            response,
            nonce,
            ec.ECDSA(hashes.SHA256())  # Using ECDSA with SHA-256
        )
        return True
    except InvalidSignature:
        return False
    

def void(*args, **kwargs):
    pass

















import getpass


class RunContext(Enum):
    AUTO_DETECT = 1
    INTERACTIVE = 2

# class Console:
#     def __init__(self, context: RunContext):
#        self.context: RunContext = context
#     
#     def log(self, *args, **kwargs):
#         if self.context == RunContext.AUTO_DETECT:
#            print(*args, **kwargs)

__KNOWN_WEBSITES__: Dict[str, str] = {
    'Microsoft': 'login.microsoft.com',
    'WPI': 'login.microsoft.com/v3/SSO',
    'Google': 'accounts.google.com',
    'Yahoo': 'login.yahoo.com',
    'Facebook': 'www.facebook.com',
    'Twitter': 'twitter.com',
    'GitHub': 'github.com'
}

def bytes_to_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value)

class UserFacingConnection:
    def __init__(self, connection: Connection):
        self.connection: Connection = connection
    def execute(self, action: ConnectionAction) -> bool:
        if action == ConnectionAction.Show_Account_Tables:
            return self.connection.website.display_table()
        if action == ConnectionAction.Login:
            return self.connection.login()
        if action == ConnectionAction.CreateNewAccount:
            return self.connection.website.create_new_account(self.connection)
        if action == ConnectionAction.Logout:
            return self.connection.website.end_session(self.connection.session_token)
        if action == ConnectionAction.Update_Password:
            return self.connection.website.update_account_password(self.connection.session_token)
        if action == ConnectionAction.View_Account_Info:
            return self.connection.website.view_account_info(self.connection.session_token)
        if action == ConnectionAction.Update_MFA:
            return self.connection.website.update_account_MFA(self.connection.session_token)

    def available_actions(self) -> List[ConnectionAction]:
        return [
            ConnectionAction.Login,
            ConnectionAction.CreateNewAccount,
            ConnectionAction.Show_Account_Tables,
            ConnectionAction.Close_Connection
        ] if not self.is_logged_in() else [
            ConnectionAction.View_Account_Info,
            ConnectionAction.Update_Password, 
            ConnectionAction.Update_MFA, 
            ConnectionAction.Logout,
            ConnectionAction.Show_Account_Tables,
            ConnectionAction.Close_Connection
        ]
        
    def is_logged_in(self) -> bool:
        return self.connection.is_logged_in()

class UserInterface:
    def __init__ (self, run_context: RunContext):
        self.console: Colors = Colors(display=(run_context == 1))
        self.clients: Dict[str, Client] = {}
        self.YubiKeys = {}

    def approve_mfa_registration_request(self, request: MFARegistrationRequest, by_client: Client) -> Optional[MFARegistrationApproval]:
        console.log('UserInterface').print(f" $UserInterface: Recieved mfa registration request from Client({by_client.name}) on behalf of RP({request.RP_ID}).")
        if len(self.YubiKeys) == 0:
            console.log('UserInterface').print(f" $UserInterface: No YubiKeys registered on this device. You do not have the ability approve this request.")
            console.log('UserInterface').print(f" $UserInterface: Registration request timmed out.")
            return None
        console.log('UserInterface').print(f" $UserInterface: Here are a list of your YubiKeys:")
        base_buff: str = ' ' * len(' $UserInterface:')
        for i, yk in enumerate(self.YubiKeys.keys()):
            console.log('UserInterface').print(f"{base_buff}\t {i + 1}. '{yk}'")
        console.log('UserInterface').print(f"{base_buff}\t {i + 2}. deny registration request")
        console.log('UserInterface').post()
        inp = input(f" $UserInterface: Please select a YubiKey to approve (or {i + 2} to deny) > {Colors.CLEAR}")
        yk_name: Optional[str] = None
        try:
            ichoice = int(inp)
            yk_name = (list(self.YubiKeys.keys()) + ['deny registration request'])[ichoice - 1]
        except ValueError:
            for yk in list(self.YubiKeys.keys()) + ['deny registration request']:
                if yk.startswith(inp):
                    yk_name = yk
                    break
        if not yk_name:
            console.log('UserInterface').print(f" $UserInterface: Invalid choice '{inp}'. Registration request timmed out.")
            return None
        if yk_name == 'deny registration request':
            console.log('UserInterface').print(f" $UserInterface: Registration request denied.")
            return None
        yk: YubiKey = self.YubiKeys[yk_name]
        approval: MFARegistrationApproval = yk.register_account(request)
        console.log('UserInterface').print(f" $UserInterface: Reclieved approved registration request from YubiKey({yk.ID}) for RP({request.RP_ID}) on behalf of user {request.username}.")
        console.log('UserInterface').print(f" $UserInterface: Passing approval to Client({by_client.name}).")
        return approval



    def new_YubiKey(self) -> str:
        secret = os.urandom(32)
        YK = YubiKey(secret)
        self.YubiKeys[YK.ID] = YK
        console.log('YubiKey Factory').print(f"     $YubiKey Factory: creating new YubiKey with ID = {YK.ID}")
        console.log('YubiKey Factory').print(f"     $YubiKey Factory: hardcoded Yubikey({YK.ID}) with the following secret key: 64{bytes_to_base64(secret)}")
        global state_saved
        state_saved = False
        return YK.ID
    
    def digest_YubiKey_strings(self, yk_strings: List[str]) -> List[str]:
        YubiKeys: List[YubiKey] = [YubiKey.from_string(yk) for yk in yk_strings if yk not in ['', ' ', '\t']]
        self.set_YubiKeys(
            YubiKeys
        )
        return [yk.ID for yk in YubiKeys]
    
    def set_YubiKeys(self, YubiKeys: List[YubiKey]) -> None:
        for yk in YubiKeys:
            self.YubiKeys[yk.ID] = yk
            console.log('UserInterface').print(f" $UserInterface: setting YubiKey({yk.ID}) and restoring old secret ...")

    def boot_client(self, client_name='Chome.exe') -> Client:
        if client_name not in self.clients.keys():
            console.log('UserInterface').print(f' $UserInterface: creating new client "{client_name}"')
            self.clients[client_name] = Client(client_name)
            global state_saved
            state_saved = False
        else:
            console.log('UserInterface').print(f' $UserInterface: client "{client_name}" already exists, restarting client...')
        return self.clients[client_name]

    def _get_connection(self, client_name, website):
        if client_name not in self.clients.keys():
            console.log('UserInterface').print(f' $UserInterface: creating new client "{client_name}"')
            self.clients[client_name] = Client(client_name)
            global state_saved
            state_saved = False
        client = self.clients[client_name]
        return client.connect(website, self)

    def connect_to_internet(self, client_name, website):
        console.log('UserInterface').print(f' $UserInterface: requesting Client({client_name}) to connect to {website}')
        return UserFacingConnection(self._get_connection(client_name, website))

    def update_backend_settings(self, display: bool):
        global console
        console.set_backend_display(display)

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
                self.console.log(f' ${RP.name}: Username or Password incorrect. Access denied. (1FA Fail)')
                if input(f'UserInterface: Try again? (Y/n) > ').lower() in ['y', 'yes']:
                    continue
                return False
            break
        if RP.requires_2FA(username):
            self.console.log(f' ${RP.name}: usr="{username}" requires 2FA...')
            self.console.log(f' ${RP.name}: insert and auth using YubiKey for the respective account.')
            if len(self.YubiKeys.keys()) == 0:
                print(f'UserInterface ERR: No YubiKeys found. Add one first.')
                return False
            while True:
                resp = input(f'UserInterface: Enter YubiKey ID or enter "-SHOW YUBIKEY IDs" to view all known YubiKey IDs > ')
                
        print(f'$ {RP.name}: Successfully logged in as "{username}". Access granted')
    """
    def insert_yubikey(self) -> Optional[int]:
        while True:
            resp = input(f'UserInterface: Enter YubiKey ID or enter "-SHOW YUBIKEY IDs" to view all known YubiKey IDs > {Colors.CLEAR}')
            if resp.lower() == '-show yubikey ids':
                console.log('UserInterface').print('UserInterface: YubiKey IDs:')
                for id, YK in self.YubiKeys.items():
                    console.log('UserInterface').print(f'  {id}: {YK}')
                continue
            try:
                id = int(resp)
                if id in self.YubiKeys.keys():
                    console.log('UserInterface').print(f'UserInterface: YubiKey({id}) inserted into computer...')
                    return id
            except ValueError:
                console.log('UserInterface').post()
                if input(f'UserInterface: No such key ("{id}"), try again (Y/n)? {Colors.CLEAR}').lower() in ['y', 'yes']:
                    console.clear()
                    continue
                console.clear()
                console.log('UserInterface').print(f"UserInterface: You didn't enter a YubiKey in time!")
                return None
    # will always return bytes, may be wrong but will always return bytes (never None)
    def YubiKey_auth(self, ykID: int, challenge: Challenge) -> Optional[YubiKeyResponse]:
        YK: YubiKey = self.YubiKeys[ykID]
        return YK.auth_2FA(challenge)
    
    def YKs_to_string(self):
        result: List[str] = []
        for _, yk in self.YubiKeys.items():
            result.append(f'<YubiKey>{yk.ID}, {yk._device_secret}</YubiKey>')
            print(f'{yk._device_secret}')
        return result
    
        