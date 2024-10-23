# SECTION::DEF make sure everything is installed before importing
import packagemanager


# SECTION::DEF import libraries
import os
import re
import base64
import hmac
from hashlib import sha256
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from yubico_client.yubico import Yubico
from terminal import running_on_PowerShell
import readline
import time
import datetime
import string
import random
import json
from enum import Enum
from typing import Optional, List, Dict
from display import Colors
import pyotp
import qrcode_terminal
import qrcode



# SECTION::DEF global variables
debug_mode: bool = False
reinstating: bool = True
state_saved: bool = True
display_backend: bool = True
console: Colors = Colors(display=True, backend=True)
WEBSITES: Dict[str, 'RelyingParty'] = {}
cursor: str = '|/-\\'
edit_classes_pre_intialization: Dict[str, bool] = {
    'RelyingParty': False,
    'Account': False,
    'SessionToken': False,
    'MFARegistrationRequest': False,
    'MFARegistrationApproval': False,
    'YubiKey': False,
    'YubiKeyResponse': False,
    'Challenge': False
}

CONFIG_FILE: str = "yubico_config.json"
ISSUER_NAME: str = 'PhishingDemo'


# SECTION::DEF begin class definitions
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
    def __init__(self, RP_name: str, password: str, salt: Optional[bytes] = None, display: bool = True, RP_Forwarding:Optional[str]=None):
        self.RP_name = RP_name
        self.RP_pretending_to_be: Optional[str] = f'{RP_Forwarding} -> ' if RP_Forwarding else None
        if salt is None:
            global cursor
            for i in range(12):
                Hasher.print_backend(self.RP_name, display, f'No salt provided ... Generating random salt: {cursor[i%len(cursor)]}', end='\r', f=self.RP_pretending_to_be)
                if not reinstating:time.sleep(0.1)
            salt = os.urandom(32)
            Hasher.print_backend(self.RP_name, display, f'No salt provided ... Generating random salt: {bytes_to_base64(salt)}  ', f=self.RP_pretending_to_be)
        Hasher.print_backend(self.RP_name, display, f'Initializing Hasher object from password="{password}" and salt={bytes_to_base64(salt)}...', f=self.RP_pretending_to_be)
        self.salt = salt
        self.hashed_password = self._hash_password(password, salt)

    def _hash_password(self, password: str, salt: bytes, display=display_backend) -> str:
        Hasher.print_backend(self.RP_name, display, f'Using Argon2 to hash password...', f=self.RP_pretending_to_be)
        ph = PasswordHasher()
        return ph.hash(password.encode(), salt=salt)

    def hash_str(self, display=display_backend, _force=False) -> str:
        if _force:
            return f"{self.hashed_password}:{self.salt.hex()}"
        global cursor
        global reinstating
        for i in range(12):
            Hasher.print_backend(self.RP_name, display, f'Generating hash string... {cursor[i%len(cursor)]}', end='\r', f=self.RP_pretending_to_be)
            if not reinstating: time.sleep(0.1)
        Hasher.print_backend(self.RP_name, display, f'Generating hash string... (i.e. "[hashed_password]:[salt]")', f=self.RP_pretending_to_be)
        Hasher.print_backend(self.RP_name, display, f'Resulting hash: "{self.hashed_password}"', f=self.RP_pretending_to_be)
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
        provided_hasher = Hasher(self.RP_name, password, salt=bytes.fromhex(self.salt.hex()))
        return provided_hasher == self
    @staticmethod
    def is_correct_password(RP_name: str, password: str, hash_string: str, f:Optional[str]=None) -> bool:
        stored_hasher = Hasher.from_hash_string(RP_name, hash_string, f=f)
        provided_hasher = Hasher(RP_name, password, salt=bytes.fromhex(stored_hasher.salt.hex()))
        return provided_hasher == stored_hasher

    @staticmethod
    def from_hash_string(RP_name: str, hash_string: str, display=display_backend, f:Optional[str]=None) -> 'Hasher':
        Hasher.print_backend(RP_name, display, f'Creating Hasher object from hash string: {hash_string}', f=f)
        hashed_password, salt = hash_string.split(':')
        salt = bytes.fromhex(salt)
        Hasher.print_backend(RP_name, display, f'Extracted salt: {bytes_to_base64(salt)}', f=f)
        hasher = Hasher(RP_name, "", salt=salt)  
        hasher.hashed_password = hashed_password  
        return hasher
    @staticmethod
    def print_backend(RP_name: str, display: bool, message: str, end='\n', f:Optional[str]=None) -> None:
        if display:#      'crypto_backend.HashObject:'
            crypto_type = f.ljust(29) if f else 'crypto_backend.HashObject:   '
            print('       ', end='')
            console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', f'{crypto_type}', f" {message}", end=end)

class YubiKeyResponse:
    def __init__(self, signature: bytes, nonce: bytes, YubiKeyID: str):
        self.signature: bytes = signature
        self.nonce: bytes = nonce
        self.YubiKeyID: str = YubiKeyID

class MFARegistrationRequest:
    def __init__(self, RP_ID: str, username: str):
        self.RP_ID: str = RP_ID
        self.username: str = username

class MFARegistrationApproval:
    def __init__(self, public_key: str, YubiKeyID: str):
        self.public_key: str = public_key
        self.YubiKeyID: str = YubiKeyID

class YubiKey:
    def __init__(self, secret:Optional[bytes]=None, ID:Optional[str]=None, _first_time=True):
        global edit_classes_pre_intialization
        if edit_classes_pre_intialization['YubiKey']:
            try:
                s = 'None' if not secret else f'"{bytes_to_base64(secret)}"'
                question: str = f'         --dbuger YubiKey.__init__(ID="{ID}", secret={s}) override? (Y/n) > {Colors.MAGENTA}'
                Colors.clear_display()
                set_readline(['yes', 'no'])
                console.log('Debugger_Override').post()
                if input(question).lower() in ['y', 'yes']:
                    set_readline([])
                    console.log('Debugger_Override').post()
                    ID = input(f'         --dbuger YubiKey.__init__(ID="{Colors.MAGENTA}')
                    Colors.clear_display()
                    console.log('Debugger_Override').post()
                    s = input(f'{Colors.REVERSE_NEWLINE}         --dbuger YubiKey.__init__(ID="{ID}", secret="{Colors.MAGENTA}')
                    Colors.clear_display()
                    secret = None if s.lower() == 'none' else s
                    s = 'None' if s.lower() == 'none' else f'"{s}"'
                    console.log('Debugger_Override').print(f'{Colors.REVERSE_NEWLINE}{Colors.CYAN}         --dbuger YubiKey.__init__(ID="{ID}", secret={s})')
                    console.log('Debugger_Override').print(f'         --OVERRIDE::YubiKey.__init__(ID="{ID}", secret={s})')
                    Colors.clear_display()
                    time.sleep(1)
                set_readline([])
            except KeyboardInterrupt:
                Colors.clear_display()

        if not secret:
            secret = YubiKey._gen_secret(print_fun=True)
        if not ID:
            ID = get_rand_id(12)
        global reinstating
        self._device_secret: bytes = secret
        self.ID: str = ID
        msg = 'Initializing for the first time...'
        global state_saved
        if not _first_time:
            msg = 'Reloading ...'
        else:
            state_saved = False
        console.log('YubiKey').print(f'$YK({self.ID}): {msg}')
        if not reinstating: time.sleep(0.1)
    
    def __str__(self) -> str:
        return f'<YubiKey>id={self.ID}, device_secret=0x{self._device_secret.hex()}</YubiKey>'

    def __repr__(self) -> str:
        return self.__str__()

    def register_account(self, request: MFARegistrationRequest) -> MFARegistrationApproval:
        global cursor
        global reinstating
        for i in range(12):
            console.log('YubiKey').print_backend(
                f'$YK({self.ID})', 
                '.crypto_backend.approval :', 
                f'Calculating private key for RP({request.RP_ID}) + User="{request.username}@{request.RP_ID}" {cursor[i%len(cursor)]}',
                end='\r')
            if not reinstating: time.sleep(0.1)
        console.log('YubiKey').print_backend(
            f'$YK({self.ID})', 
            '.crypto_backend.approval :', 
            f'Calculating private key for RP({request.RP_ID}) + User="{request.username}@{request.RP_ID}"  ')
        id = {get_rand_id(10)}
        console.log('YubiKey').print_backend(
            f'$YK({self.ID})', 
            '.crypto_backend.approval :', 
            f'Calculated PrivateKey({id}) for RP({request.RP_ID}) + User="{request.username}@{request.RP_ID}"')
        for i in range(7):
            console.log('YubiKey').print_backend(
                f'$YK({self.ID})', 
                '.crypto_backend.approval :', 
                f'Calculating public key for PrivateKey({id}) {cursor[i%len(cursor)]}',
                end='\r')
            if not reinstating: time.sleep(0.1)
        _, public_key = self._generate_key_pair(request.RP_ID, request.username)
        pubk: str = f'{bytes_to_base64(YubiKey.public_key_to_bytes(public_key))}'
        console.log('YubiKey').print_backend(
            f'$YK({self.ID})', 
            '.crypto_backend.approval :',
            f'Calculated PublicKey({pubk}) for PrivateKey({id})')
        console.log('YubiKey').print_backend(
            f'$YK({self.ID})', 
            '.crypto_backend.approval :',
            f'Returning PublicKey({pubk}) to Operating System')
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
        public_key_bytes = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)

        # display(f"Public Key (Compressed): {public_key_bytes.hex()}")
        # display(f'Private Key {YubiKey._private_key_to_number(private_key)}')
        return (private_key, public_key)
    
    def auth_2FA(self, challenge: 'Challenge') -> YubiKeyResponse:
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
    def get_OTP() -> Optional[str]:
        try:
            set_readline([])
            otp = input(f"YubiKey OTP > {Colors.CYAN}")
            print(Colors.CLEAR, end='')
            if len(otp) != 44:
                print(f"{Colors.RED}Invalid OTP length. Please try again.{Colors.CLEAR}")
                return None
            return otp
        except Exception as e:
            print(Colors.CLEAR, end='')
            raise e
    @staticmethod
    def validate_OTP(username: str, yubikey_identifier, otp: Optional[str] = None) -> bool:
        try:
            while not otp:
                otp = YubiKey.get_OTP()
            if len(otp) != 44:
                print(f"{Colors.RED}Invalid OTP length. Please try again.{Colors.CLEAR}")
                return False
            yubikey_public_id = otp[:12]
            if yubikey_public_id != yubikey_identifier:
                print(f"{Colors.RED}YubiKey public ID does not match for user '{username}'.{Colors.CLEAR}")
                return False
            return YubiKey.verify_otp_origin(otp)
        except KeyboardInterrupt:
            return False
        except Exception as e:
            print(Colors.CLEAR, end='')
            raise e
    @staticmethod
    def verify_otp_origin(otp: str) -> bool:
        config = YubiKey.load_yubico_config()
        yubico = Yubico(config["YUBICO_CLIENT_ID"], config["YUBICO_SECRET_KEY"])
        try:
            # Send the OTP to Yubico's validation service
            if yubico.verify(otp):
                print(f"{Colors.GREEN}YubiKey OTP is valid!{Colors.CLEAR}")
                return True
            else:
                print(f"{Colors.RED}YubiKey OTP is invalid.{Colors.CLEAR}")
                return False
        except Exception as e:
            print(f"{Colors.RED}YubiKey OTP is invalid.")
            print(f"Error verifying YubiKey OTP: {e}")
            print(Colors.CLEAR, end='')
            return False

    @staticmethod
    def load_yubico_config():
        """Load Yubico client ID and secret key from a config file."""
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as file:
                return json.load(file)
        else:
            raise FileNotFoundError(f"{Colors.RED}Config file '{CONFIG_FILE}' not found.{Colors.CLEAR} Please add the Yubico API credentials.")

    @staticmethod
    #   public_key_to_bytes(public_key: ec._EllipticCurvePublicKey) -> bytes:
    def public_key_to_bytes(public_key                            ) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    @staticmethod
    def bytes_to_public_key(public_key_bytes: bytes): # -> ec._EllipticCurvePublicKey:
        if not isinstance(public_key_bytes, bytes):
            raise TypeError("Expected bytes")
        try:
            return serialization.load_pem_public_key(
                public_key_bytes,
                backend=default_backend()
            )
        except Exception as e:
            raise ValueError(f"Failed to deserialize public key: {e}")

    @staticmethod
    def _private_key_to_number(private_key) -> int:
        return private_key.private_numbers().private_value
    
    @staticmethod
    def from_string(s: str) -> 'YubiKey':
        id_pattern = r"<YubiKey>id=([A-Za-z0-9]+), "
        secret_pattern = r" device_secret=0x(.*?)</YubiKey>"
        # secret_backup_pattern = r', b"(.*?)"'
        id_match = re.search(id_pattern, s)
        secret_match = re.search(secret_pattern, s)
        # secret_backup_match = re.search(secret_backup_pattern, s)
        yk_id = id_match.group(1) if id_match else None
        # device_secret_str = eval(f"b'{secret_match.group(1)}'") if secret_match else eval(f'b"{secret_backup_match.group(1)}"') if secret_backup_match else None
        device_secret: bytes = bytes.fromhex(secret_match.group(1)) if secret_match else None
        yk = YubiKey(secret=device_secret, ID=yk_id, _first_time=False)
        return yk
    
    
    @staticmethod
    def _gen_secret(print_fun=False) -> bytes:
        global cursor
        for i in range(18):
            console.log('YubiKey').print(f"No secret specified. Generating random secret {cursor[i%len(cursor)]}", end='\r')
        secret = os.urandom(32)
        console.log('YubiKey').print(f"No secret specified. Generating random secret {secret}")
        return secret
    
class Account:
    def __init__(self, name: str, hash: Hasher, pk=None, pk_id: Optional[str] = None, mfa: str = 'None'):
        self.mfa_type: str = mfa # 'None', 'Auth App', 'OTP', 'FIDO-2'
        self.name: str = name
        self._hasher_object: Hasher = hash
        self.password_hash: str = ''
        self.salt: str          = ''
        self.password_hash, self.salt = self._hasher_object.hash_str().split(':')
        self.public_key = pk
        self.public_key_to_display = pk_id
        global state_saved
        state_saved = False

    def has_same_password(self, RP_name: str, password: str, f:Optional[str]=None) -> bool:
        return Hasher.is_correct_password(
            RP_name,
            password, 
            self._hasher_object.hash_str(),
            f=f
        )

    def __str__(self) -> str:
        if self.public_key and self.mfa_type.upper() == 'FIDO-2':
            return f'<Account>Username={self.name}<br-splitter>Password={self.password_hash}:{self.salt}<br-splitter>public_key=0x{YubiKey.public_key_to_bytes(self.public_key).hex()}<br-splitter>public_key_to_display={self.public_key_to_display}<br-splitter>mfa_type=FIDO-2</Account>'
        elif self.public_key and self.mfa_type.upper() == 'OTP':
            return f'<Account>Username={self.name}<br-splitter>Password={self.password_hash}:{self.salt}<br-splitter>Yubico_ID={self.public_key}<br-splitter>public_key_to_display={self.public_key_to_display}<br-splitter>mfa_type=OTP</Account>'
        elif self.public_key:
            return f'<Account>Username={self.name}<br-splitter>Password={self.password_hash}:{self.salt}<br-splitter>AuthenticatorAppSecret={self.public_key}<br-splitter>public_key_to_display={self.public_key_to_display}<br-splitter>mfa_type=AuthApp</Account>'
        return f'<Account>Username={self.name}<br-splitter>Password={self.password_hash}:{self.salt}<br-splitter>public_key=None<br-splitter>public_key_to_display=None<br-splitter>mfa_type=None</Account>'

    def __repr__(self) -> str:
        return self.__str__()

    @staticmethod
    def from_string(RP_name: str, account_string: str) -> 'Account':
        otp: bool = 'mfa_type=OTP' in account_string
        otc: bool = 'mfa_type=AuthApp' in account_string
        fido_or_none = not otp and not otc
        print(f'\n\tDEBUGGER: {otp=}, {otc=}')
        username_pattern = r"Username=(.*?)<br-splitter>"
        password_pattern = r"Password=(.*?)<br-splitter>"
        public_key_pattern = r"public_key=(.*?)<br-splitter>"
        if otp:
            public_key_pattern = r"<br-splitter>Yubico_ID=(.*?)<br-splitter>"
        elif otc:
            public_key_pattern = r"<br-splitter>AuthenticatorAppSecret=(.*?)<br-splitter>"
        public_key_to_display_pattern = r"<br-splitter>public_key_to_display=(.*?)<br-splitter>"

        # Extract the username, password hash, and public key using regex
        username_match = re.search(username_pattern, account_string)
        password_match = re.search(password_pattern, account_string)
        public_key_match = re.search(public_key_pattern, account_string)
        public_key_to_display_match = re.search(public_key_to_display_pattern, account_string)

        # Get the matches, convert password hash to bytes, handle public key 'None'
        username = username_match.group(1) if username_match else None
        password_hash_str = password_match.group(1) if password_match else None
        if debug_mode:
            print(f'{Colors.CYAN} --d for account={username} {public_key_match.group(1)=}'[:60] + f'{Colors.CLEAR}')
        print(f'\tDEBUGGER: {public_key_match=}')
        pk_m = public_key_match.group(1) if public_key_match else None
        pk_v: Optional[str] = pk_m if pk_m != 'None' else None
        if fido_or_none:
            public_key = YubiKey.bytes_to_public_key(
                bytes.fromhex(pk_v[2:])
            ) if pk_v else None
        else:
            public_key = pk_v if pk_v else None
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
        mfa_type = 'None'
        if otp:
            mfa_type = 'OTP'
        elif otc:
            mfa_type = 'Auth App'
        elif 'mfa_type=FIDO-2' in account_string:
            mfa_type = 'FIDO-2'
        account: Account = Account(username, Hasher.from_hash_string(RP_name, password_hash_str), pk=public_key, pk_id=public_key_to_display, mfa=mfa_type)
        return account
    @staticmethod
    def split(RP_name: str, s: str) -> List['Account']:
        l: List[Account] = []
        for account_string in s.split('</Account>'):
            if account_string in ['{}', ' ', '', '\t', ']', '[', '[]']:
                continue
            acc: Account = Account.from_string(RP_name, account_string + '</Account>')
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
        self.ID = get_rand_id(8)

        # hidden
        self._expires_on = int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + hours * 3600
        self._data = data
        self._value_string = f'Account={self.for_account},atype={self.auth_type},expires={self._expires_on},nonce={self._data.hex()}'
        RP: RelyingParty = by_connection.website
        note = '' if auth_type_required == auth_type else f'Note: this user requires auth_type={auth_type_required}'
        console.log('RelyingParty').print_backend(f'       $RP({RP.name}).', 'crypto_backend.SessionToken: ', f" Going to generate SessionToken with auth_type={self.auth_type} for user={account}@{RP.name}.{note}")
        global cursor
        global reinstating
        for i in range(12):
            console.log('RelyingParty').print_backend(f'       $RP({RP.name}).', 'crypto_backend.SessionToken: ', f" Generating SessionToken {cursor[i%len(cursor)]}", end='\r')
            if not reinstating: time.sleep(0.1)
        console.log('RelyingParty').print_backend(f'       $RP({RP.name}).', 'crypto_backend.SessionToken: ', f" Generated SessionToken with auth_type={self.auth_type} for user={account}@{RP.name}")
    
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
    def __init__(self, RP: 'RelyingParty', username: str, token_1FA: 'SessionToken', NonceID: str, Nonce: bytes):
        RP_name = RP.name if RP.name == RP._pretending_to_be else RP._pretending_to_be
        global reinstating
        global edit_classes_pre_intialization
        global cursor
        if edit_classes_pre_intialization['Challenge']:
            try:
                question: str = f'         --dbuger Challenge.__init__(RP_name="{RP_name}", username="{username}", nonce="{bytes_to_base64(Nonce)}") override? (Y/n) > {Colors.MAGENTA}'
                Colors.clear_display()
                set_readline(['yes', 'no'])
                console.log('Debugger_Override').post()
                if input(question).lower() in ['y', 'yes']:
                    set_readline([])
                    console.log('Debugger_Override').post()
                    RP_name = input(f'         --dbuger Challenge.__init__(RP_name="{Colors.MAGENTA}')
                    Colors.clear_display()
                    console.log('Debugger_Override').post()
                    username = input(f'{Colors.REVERSE_NEWLINE}         --dbuger Challenge.__init__(RP_name="{RP_name}", username="{Colors.MAGENTA}')
                    Colors.clear_display()
                    console.log('Debugger_Override').post()
                    resp = input(f'{Colors.REVERSE_NEWLINE}         --dbuger Challenge.__init__(RP_name="{RP_name}", username="{username}", nonce="{Colors.MAGENTA}')
                    Colors.clear_display()
                    Nonce = base64_to_bytes(resp)
                    console.log('Debugger_Override').print(f'{Colors.REVERSE_NEWLINE}         --dbuger Challenge.__init__(RP_name="{RP_name}", username="{username}", nonce="{bytes_to_base64(Nonce)}")')
                    console.log('Debugger_Override').print(f'         --OVERRIDE::Challenge.__init__(RP_name="{RP_name}", username="{username}", nonce="{bytes_to_base64(Nonce)}")')
                    Colors.clear_display()
                    for i in range(8):
                        console.log('Debugger_Override').print(f'         --OVERRIDE::RP.name("{RP_name}") for length of Challenge creation {cursor[i%len(cursor)]}', end='\r')
                        if not reinstating: time.sleep(0.1)
                    console.log('Debugger_Override').print(f'         --OVERRIDE::RP.name("{RP_name}") for length of Challenge creation - success')
                set_readline([])
            except KeyboardInterrupt:
                Colors.clear_display()
                return
            except Exception as e:
                Colors.clear_display()  
                raise Exception


        self.RP_ID = RP_name
        self.username = username
        self.token_1FA = token_1FA
        self.NonceID = NonceID
        self.nonce = Nonce
        nonce_cut = f'{Nonce}'[:20] + '...'
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f' Generating challenge ...')
        if not reinstating: time.sleep(0.2)
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'     Challenge(')
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'         user={username}@{RP_name}, ')
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'         SessionToken({token_1FA.ID}),')
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'         Nonce(id={NonceID}),')
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'         bytes_value={nonce_cut}')
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f'     )')
        for i in range(16):
            console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f' Signing challenge using RP({RP_name}) {cursor[i%len(cursor)]}', end='\r')
            if not reinstating: time.sleep(0.1)
        console.log('RelyingParty').print_backend(f'       $RP({RP_name}).', 'crypto_backend.ChallengeGen: ', f' Signing challenge using RP({RP_name}) - success')


class RelyingParty:
    def __init__(self, name: str, _pretending_to_be: Optional[str] = None, __account_ptr: Optional[str] = None):
        self.name: str = name
        self._pretending_to_be: str = self.name if not _pretending_to_be else _pretending_to_be
        self._account_ptr: Optional[str] = __account_ptr
        self.accounts: Dict[str, Account] = {}
        self._longest_account_length: int = len('Username')  # used for displaying in table
        self.tokens: Dict[str, SessionToken] = {}
        self.INDENT: str = "     "
        self.classname: str = 'RelyingParty'
        self.p(f'initializing for the first time...')
        global Tracker
        global reinstating
        global state_saved
        Tracker.append(self)
        if not reinstating: 
            time.sleep(0.2 + 0.05 * len(self.accounts.keys()))
            state_saved = False

    def __str__(self) -> str:
        accounts: List[Account] = []
        for a_name in self.accounts.keys():
            accounts.append(self.accounts[a_name])
        return f'RelyingParty({self.name}||SEPER||_pretending_to_be={self._pretending_to_be})=||STARTER||{accounts}||SEPER||{self._longest_account_length}||ENDER||'

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
            self.p(f'\tUsername:      {acc.name}')
            self.p(f'\tPassword Hash: {bytes_to_base64(acc.password_hash.encode("utf8"))}'[:100])
            self.p(f'\tPassword Salt: {acc.salt}')
            pub = 'None'
            if acc.mfa_type.upper() == 'FIDO-2' and acc.public_key:
                pub = f'{YubiKey.public_key_to_bytes(acc.public_key)}'.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("\n-----END PUBLIC KEY-----\n", "")
            elif acc.public_key:
                pub = f'YubiKeyID={acc.public_key}'
            self.p(f'\tPublic Key:    {pub}')
            return True
        except KeyboardInterrupt as ki:
            return False

    def update_account_MFA(self, session: Optional[SessionToken], mfa_method: Optional[str] = None) -> Optional[bool]:
        try:
            console.log('RelyingParty').post()
            set_readline(['Auth App', 'OTP', 'FIDO-2'])
            while not mfa_method:
                resp = input(f'     $RP({self.name}): Register MFA type: Auth App, OTP, or FIDO-2? > ')
                if resp.upper() in ['AUTH APP', 'OTP', 'FIDO-2']:
                    set_readline([])
                    mfa_method = resp.upper()
                    break
            if mfa_method == 'FIDO-2':
                return self.update_account_MFA_FIDO2(session)
            elif mfa_method == 'OTP':
                return self.update_account_MFA_OTP(session)
            else:
                return self.update_account_MFA_Auth_App(session)
        except KeyboardInterrupt:
            return None

    def update_account_MFA_Auth_App(self, session: Optional[SessionToken]) -> bool:
        global reinstating
        try:
            global ISSUER_NAME
            global state_saved
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
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . . .')
            if not reinstating: time.sleep(0.05)

            console.log('Client').print(f'   $Client({client.name}): Recieved request for Auth App MFA from RP({self.name})')
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System . .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System . . .')
            if not reinstating: time.sleep(0.05)

            console.log('OperatingSystem').print(f' $OperatingSystem: Scan the qr code and hit enter when ready or Ctrl+C to quit.')
            qr: QR_Code = QR_Code.generate(session.for_account, issuer_name=ISSUER_NAME)
            qr.display(confirm=True)
            self.accounts[session.for_account].public_key = qr.get_secret()
            self.accounts[session.for_account].mfa_type = 'Auth App'
            state_saved = False
            return True
        except KeyboardInterrupt:
            False

    def update_account_MFA_OTP(self, session: Optional[SessionToken]) -> bool:
        global reinstating
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
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . . .')
            if not reinstating: time.sleep(0.05)

            console.log('Client').print(f'   $Client({client.name}): Recieved request for OTP from RP({self.name})')
            console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System . .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System . . .')
            if not reinstating: time.sleep(0.05)

            console.log('OperatingSystem').print(f' $OperatingSystem: Insert YubiKey into USB port')
            console.log('OperatingSystem').print(f' $OperatingSystem: Press YubiKey when prompted . . .')

            otp: Optional[str] = YubiKey.get_OTP()
            if not otp:
                console.log('OperatingSystem').print(f' $OperatingSystem: YubiKey OTP failed')
                time.sleep(0.01)
                console.log('Client').print(f'   $Client({client.name}): Failed to recieve OTP from Operating System . . .')
                time.sleep(0.01)
                self.p(f'Did not receive OTP from Client({client.name}) in time.')
                self.p(f'"MFA add" attempt failed.')
                return False
            time.sleep(0.25)
            console.log('OperatingSystem').print(f' $OperatingSystem: Sending YubiKey OTP({otp}) to Client({client.name})')
            time.sleep(0.01)
            console.log('Client').print(f'   $Client({client.name}): Received OTP({otp}) from Operating System')
            console.log('Client').print(f'   $Client({client.name}): Sending YubiKey OTP to RP({self.name})')
            time.sleep(0.01)
            self.p(f'Received OTP({otp}) from Client({client.name})')
            yubikey_identifier = otp[:12]
            self.p(f'Registering Yubikey with ID({yubikey_identifier}) to user={session.for_account}@{self.name}')
            self.accounts[session.for_account].public_key = yubikey_identifier
            self.accounts[session.for_account].mfa_type = 'OTP'
            self.p(f'Updated MFA method to "OTP" for user="{session.for_account}@{self.name}"')
            self.show_table_question()
            global state_saved
            state_saved = False
            return True
        except KeyboardInterrupt as ki:
            return False

    def update_account_MFA_FIDO2(self, session: Optional[SessionToken]) -> bool:
        global reinstating
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
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . .', end='\r')
            if not reinstating: time.sleep(0.1)
            self.p(f'Sending request to Client({client.name}) . . .')
            if not reinstating: time.sleep(0.05)
            
            request: MFARegistrationRequest = MFARegistrationRequest(self.name, session.for_account)
            approval: Optional[MFARegistrationApproval] = client.request_registration(request, self, session.by_connection.UI_ptr)

            if not approval:
                self.p('Waiting for approval ', end='\r')
                if not reinstating: time.sleep(0.4)
                self.p('Waiting for approval .', end='\r')
                if not reinstating: time.sleep(0.4)
                self.p('Waiting for approval . .', end='\r')
                if not reinstating: time.sleep(0.4)
                self.p('Waiting for approval . . .')
                if not reinstating: time.sleep(0.4)
                self.p('Request timmed out')
                return False
            
            self.p('Waiting for approval ', end='\r')
            if not reinstating: time.sleep(0.2)
            self.p('Waiting for approval .', end='\r')
            if not reinstating: time.sleep(0.05)
            self.p(f'Recieved approval from Client({client.name})')
            self.accounts[session.for_account].public_key = approval.public_key
            self.accounts[session.for_account].mfa_type = 'FIDO-2'
            self.accounts[session.for_account].public_key_to_display = f'YK({approval.YubiKeyID})'
            self.p(f'Updated user settings for user="{session.for_account}@{self.name}" to public_key="{bytes_to_base64(YubiKey.public_key_to_bytes(approval.public_key))}"')
            self.p(f'Updated MFA method to "FIDO-2" for user="{session.for_account}@{self.name}"')
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
            if not reinstating: time.sleep(0.1)
            self.p(f'Recieved new account request from Client({client_name})')
            self.p(f'Forwarding new account message and form to Client({client_name})')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client_name}): Recieved new account message and form from RP({self.name})')
            console.log('Client').print(f'   $Client({client_name}): Printing new account message and requesting new account form from user...')
            if not reinstating: time.sleep(0.2)
            print('')
            if not reinstating: time.sleep(0.25)
            console.log('Client').print(f'   $Client({client_name}): WELCOME NEW USER TO {self.name.capitalize()}!')
            console.log('Client').print(f'   $Client({client_name}): Let\'s create a new account!')
            if not reinstating: time.sleep(0.1)
            console.log('Client').post()
            set_readline([])
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
            if not reinstating: time.sleep(0.1)
            self.p(f'{Colors.CLEAR}{Colors.GREEN_REVERSE}Caught Exception:{Colors.CLEAR}{Colors.GREEN} AccountExceptions.MFA_Missing(user={username}@{self.name}){Colors.CLEAR}')
            self.p(f'Sending message to Client({self.name}): "ACCOUNT {username.upper()} DOES NOT HAVE 2FA CONFIGURED"')
            if not reinstating: time.sleep(0.3)
            console.log(self.classname).print(f'{self.INDENT}$RP({self.name})::WARNING ACCOUNT {username.upper()} DOES NOT HAVE 2FA CONFIGURED')
            self.p(f'Account {username} created successfully!')
            self.show_table_question()
            return True
        except KeyboardInterrupt as ki:
            return False

    def show_table_question(self):
        console.log(self.classname).post()
        set_readline(['yes', 'no', 'show tables'])
        if input(f'{self.INDENT}$RP({self.name}): show table of all users (Y/n)? {Colors.CLEAR}').lower() in ['y', 'yes', 'show', 'show tables']:
            console.clear()
            self.display_table()
        set_readline([])
        console.clear()

    def _add_token(self, account: str, token: SessionToken):
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
                Hasher(self.name, account_password)
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
    def display_table(self, offset:str='') -> bool:
        pretending: str = ''
        if self.name != self._pretending_to_be:
            pretending = f' (pretending to be {self._pretending_to_be})'
        print(f"\n{offset}Relying Party '{self.name}'{pretending} accounts table:")
        dotted_line = '-' * (self._longest_account_length + 2)
        seper = f'|{dotted_line}|---------------------------------------|-----------------------------|----------|----------------------------------------|'
        print(offset + '_' * len(seper))#                                                                                                                     MFA TYPE |          Server-Side MFA Data  
        print(f'{offset}| ' + 'Username'.center(self._longest_account_length) + ' | ' + 'Password Hash (base64)'.center(37) + ' | ' + 'Password Salt (base64)'.center(27) + ' | MFA TYPE |          Server-Side MFA Data          |')
        print(offset + seper)
        for account_name, account in self.accounts.items():
            username = account_name.center(self._longest_account_length)
            MFA_TYPE = account.mfa_type.upper().center(8)# if account.mfa_type != 'None' else 'N/A'
            if account.public_key and account.mfa_type.upper() == 'FIDO-2':
                public_key = f'PublicKey={bytes_to_base64(YubiKey.public_key_to_bytes(account.public_key))}'[:35] + '...'
            elif account.public_key and account.mfa_type.upper() == 'OTP':
                public_key = f'YubiKeyID={account.public_key}'.center(38)
            elif account.public_key:
                public_key = f'OTC_Secret={account.public_key}'[:35] + '...'
            else:
                public_key = '          No Data Available           '
            hash, salt = account._hasher_object.hash_str(display=False, _force=True).split(':')
            print(f'{offset}| {username} | {str(bytes_to_base64(hash.encode()))[:34]}... | {str(bytes_to_base64(bytes.fromhex(salt.upper())))[:24]}... | {MFA_TYPE} | {public_key} |')
        print(offset + '‾' * len(seper))
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
    def get_token(self, account:str, auth_type:str, spec_token: Optional[SessionToken] = None) -> Optional[SessionToken]:
        self.prune_tokens()
        for token in self.tokens[account]:
            t: SessionToken = token
            # validate token for this user and this action
            if token.is_valid(account, auth_type) and \
                (not spec_token or token.is_same(spec_token.value())): # will only run if spec_token is not None
                return token
        return None
    def valid_login(self, username: str, password: str, f:Optional[str]=None) -> bool:
        forwarding: str = f if f else ''
        if f:
            pretending_to_be = f[f.index('Forwarding ') + 11 : f.index(' data to ')]
        replace_crypto: Optional[str] = f'{pretending_to_be} -> ' if f else None
        if username not in self.accounts.keys():
            console.log(self.classname).print(f' --d $RP({self.name}):{forwarding} Username could not be found! Sending code "HTTP 403" back to Client')
            return False
        console.log(self.classname).print(f'     $RP({self.name}):{forwarding} Hashing password with stored salt to compare against stored hashed password...')
        if not reinstating: time.sleep(0.1)
        response: bool = self.accounts[username].has_same_password(self.name, password, f=replace_crypto)
        if response:
            console.log(self.classname).print(f' --d $RP({self.name}):{forwarding} Password Hash matches! Sending code "HTTP 200" back to Client')
        else:
            console.log(self.classname).print(f' --d $RP({self.name}):{forwarding} Password Hash does not match! Sending code "HTTP 403" back to Client')
        if not reinstating: time.sleep(0.1)
        return response
    def grant_session_token_1FA(self, username: str, password: str, by_connection: 'Connection', f:Optional[str]=None) -> Optional[SessionToken]:
        forwarding: str = f if f else ''
        console.log(self.classname).print(f'     $RP({self.name}):{forwarding} Recieved Tuple(Username, Password) from Client({self.name})')
        if not reinstating: time.sleep(0.1)
        if self.valid_login(username, password, f=f):
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
            if session.timmed_out():
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) timmed out')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken to user with expired SessionToken')
                return None
            if not session.is_valid(username, '1FA'):
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is not valid for this user')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken without a valid 1FA SessionToken')
                return None
            
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is valid for this user')
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Checking YubiKey signature ...')
            if not reinstating: time.sleep(0.2)
            if is_signed(
                response.nonce,
                self.accounts[session.for_account].public_key,
                response.signature,
                self.name
            ):
                return SessionToken(session.for_account, 1, 'MFA', 'MFA', connection)
        except KeyboardInterrupt as ki:
            console.log('RelyingParty').print(f"    $RP({self.name}): MFA Inturrupted ... login failed")
            console.log('RelyingParty').print(f"    $RP({self.name}): Revoked SessionToken(Type=1FA)")
            return None
        console.log('RelyingParty').print(f"    $RP({self.name}): Cryptographic backend returned an error: Excations.Cryptographic_backend.NotDecrypted")
        global cursor
        for i in range(10):
            console.log('RelyingParty').print(f"    $RP({self.name}): Revoking SessionToken(Type=1FA) {cursor[i%len(cursor)]}", end='\r')
        console.log('RelyingParty').print(f"    $RP({self.name}): Revoked SessionToken(Type=1FA)    ")
        console.log('RelyingParty').print(f"    $RP({self.name}): MFA Failed.")
        return None
    
    def grant_session_token_MFA_using_Auth_App(
            self, 
            username: str, 
            session: SessionToken, 
            connection: 'Connection'
            ) -> Optional[SessionToken]:
        try:
            if session.timmed_out():
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) timmed out')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken to user with expired SessionToken')
                return None
            if not session.is_valid(username, '1FA'):
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is not valid for this user')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken without a valid 1FA SessionToken')
                return None
            
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is valid for this user')
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Granting MFA SessionToken to this user')
            if not reinstating: time.sleep(0.2)
            return SessionToken(session.for_account, 1, 'MFA', 'MFA', connection)
        except KeyboardInterrupt as ki:
            console.log('RelyingParty').print(f"    $RP({self.name}): MFA Inturrupted ... login failed")
            console.log('RelyingParty').print(f"    $RP({self.name}): Revoked SessionToken(Type=1FA)")
            return None

    def grant_session_token_MFA_using_OTP(
            self, 
            username: str, 
            session: SessionToken, 
            connection: 'Connection'
            ) -> Optional[SessionToken]:
        try:
            if session.timmed_out():
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) timmed out')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken to user with expired SessionToken')
                return None
            if not session.is_valid(username, '1FA'):
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is not valid for this user')
                console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Cannot grant MFA SessionToken without a valid 1FA SessionToken')
                return None
            
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' SessionToken(id={session.ID}, type={session.auth_type}) is valid for this user')
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Checking YubiKey OTP ...')
            if not reinstating: time.sleep(0.2)
            console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.SessionToken: ', f' Granting MFA SessionToken to this user')
            return SessionToken(session.for_account, 1, 'MFA', 'MFA', connection)
        except KeyboardInterrupt as ki:
            console.log('RelyingParty').print(f"    $RP({self.name}): MFA Inturrupted ... login failed")
            console.log('RelyingParty').print(f"    $RP({self.name}): Revoked SessionToken(Type=1FA)")
            return None
        
    def request_challenge(self, username: str, token: bytes, yk: YubiKey) -> Optional[Challenge]:
        self.p(f'Locating SessionToken(type=1FA) for user {username} that matches signature {token}')
        TK: Optional[SessionToken] = self.get_token(username, '1FA', token)
        if not TK:
            self.p('Permission denied - session token not found or expired')
            return None
        self.p(f'Located SessionToken({TK.ID}) for user {username} that matches signature {token}')
        console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.ChallengeGen: ', ' Generating challenge ...')
        nonce = os.urandom(32)
        console.log('RelyingParty').print_backend(f'       $RP({self.name}).', 'crypto_backend.ChallengeGen: ', f' Generated nonce: {nonce}')
        console.log(self.classname).print(f'     $RP({self.name}): generating challenge for usr="{username}", YubiKey({yk.ID})')
        return Challenge(
            self,
            username,
            token,
            TK.add_nonce(nonce),
            nonce
        )
    def requires_2FA(self, username: str, mfa_type: Optional[bool] = None) -> bool:
        if username not in self.accounts:
            raise ValueError(f'User "{username}" not found')
        if not mfa_type:
            return not not self.accounts[username].public_key
        return mfa_type.upper() == self.accounts[username].mfa_type.upper()

    @staticmethod
    def from_string(relying_party_string: str) -> 'RelyingParty':
        global WEBSITES
        rp_dict: dict = RelyingParty.extract(relying_party_string)
        rp = RelyingParty(rp_dict['name'], _pretending_to_be=rp_dict['_pretending_to_be'])
        accounts: List[Account] = rp_dict['accounts']
        ptr = rp_dict['account_pointer']
        if not ptr:
            for account in accounts:
                rp.accounts[account.name] = account
                rp.tokens[account.name] = []
        else:
            org_RP = WEBSITES[ptr]
            rp.accounts = org_RP.accounts
            rp.tokens = org_RP.tokens

            # print(f'Added account({account.name}) to RP({rp.name})')
        rp._longest_account_length = rp_dict['_longest_account_length']
        # rp.display_table()
        WEBSITES[rp.name] = rp
        for account_name in rp.accounts.keys():
                rp._longest_account_length = len(account_name) if len(account_name) > rp._longest_account_length else rp._longest_account_length
        return rp
        
        

    @staticmethod
    def extract(s: str) -> dict:
        pattern = r'RelyingParty\((?P<name>.*?)\|\|SEPER\|\|_pretending_to_be=(?P<ptb>.*?)\)=\|\|STARTER\|\|(?P<accounts>.*?)\|\|SEPER\|\|(?P<_longest_account_length>\d+)\|\|ENDER\|\|'
        basic: bool = True
        if '||STARTER||AccountPTR=' in s:
            basic = False
            pattern = r'RelyingParty\((?P<name>.*?)\|\|SEPER\|\|_pretending_to_be=(?P<ptb>.*?)\)=\|\|STARTER\|\|AccountPTR=(?P<accountptr>.*?)\|\|SEPER\|\|(?P<_longest_account_length>\d+)\|\|ENDER\|\|'
        match = re.search(pattern, s)
        if not match:
            raise ValueError("String format doesn't match the expected pattern.\nstring=" + s)
        # Constructing the dictionary with the parsed values
        RP_name: str = match.group("name")
        RP_pretending_to_be: str = match.group("ptb")
        longest_acc_name_length = int(match.group("_longest_account_length"))
        if basic:
            ptr = None
            accounts = Account.split(RP_name, match.group("accounts"))
        else:
            ptr = match.group("accountptr")
            accounts = []
        return {
            "name": RP_name,
            '_pretending_to_be': RP_pretending_to_be,
            "account_pointer": ptr,
            "accounts": accounts,
            "_longest_account_length": longest_acc_name_length
        }


class Connection:
    def __init__(self, client: 'Client', website: RelyingParty, UI_ptr: 'OperatingSystem'):
        self.client: Client = client
        self.website: RelyingParty = website
        self.session_token: Optional[SessionToken] = None
        self.UI_ptr: OperatingSystem = UI_ptr

    def request_yubikey_insert_from_OS(self, username: str) -> Optional[YubiKey]:
        c_name: str = self.client.name
        rp_name: str = self.website.name
        console.log('Client').print(f'   $Client({c_name}): Got request from RP({rp_name}) for username: {username}@{rp_name} to enter YubiKey to request Challenge.')
        console.log('Client').print(f'   $Client({c_name}): Passing request to Operating System on behalf of RP({rp_name})...')
        if not reinstating: time.sleep(0.2)
        return self.UI_ptr.insert_yubikey(self, username)
    
    

    def request_yubikey_auth_from_OS(self, ykID: int, challenge: Challenge) -> YubiKeyResponse:
        n_short: str = f'{challenge.nonce}'[:12]
        global cursor
        for i in range(8):
            console.log('YubiKey').print_backend(
                f'$YK({ykID})',  
                '.crypto_backend.authentic:', 
                f' Signing nonce({n_short}...) {cursor[i%len(cursor)]}',
                end='\r')
            if not reinstating: time.sleep(0.1)
        console.log('YubiKey').print_backend(
            f'$YK({ykID})',  
            '.crypto_backend.authentic:', 
            f' Signed nonce({n_short}...) successfully')
        console.log('YubiKey').print_backend(
            f'$YK({ykID})',  
            '.crypto_backend.authentic:', 
            f' Passing signature to OperatingSystem')
        return self.UI_ptr.YubiKey_auth(ykID, challenge)
    def login(self) -> bool:
        token: SessionToken = self.client._login_user(self)
        if token:
            self.session_token = token
            console.log('Client').print(f'   $Client({self.client.name}): Successfully logged in as "{self.session_token.for_account}"')
            if not reinstating: time.sleep(0.2)
            return True
        console.log('Client').print(f'   $Client({self.client.name}): Failed to login')
        if not reinstating: time.sleep(0.2)
        return False
    
    def is_logged_in(self) -> bool:
        return self.session_token and self.session_token.is_logged_in()


class Client:
    def __init__(self, name='Chome.exe'):
        global state_saved
        self.name = name
        console.log('Client').print(f'   $Client({self.name}): initializing for the first time...')
        if not reinstating: 
            state_saved = False
            time.sleep(0.1)

    def request_registration(self, request: MFARegistrationRequest, talking_to: RelyingParty, operating_system: 'OperatingSystem') -> Optional[MFARegistrationApproval]:
        console.log('Client').print(f'   $Client({self.name}): Recieved request for MFA registration for account="{request.username}"')
        if request.RP_ID != talking_to.name:
            console.log('Client').err(f'   $Client({self.name}): ERR: Requested registration for account="{request.username}" by unexpected RP "{request.RP_ID}" DOES NOT MATCH RP ID provided in request.')
            console.log('Client').print(f'   $Client({self.name}): Ignoring request.')
            return None
        console.log('Client').print(f'   $Client({self.name}): Verified that we are communicating with RP({talking_to.name}). This RP ID matches what was provided in the request (i.e. {request.RP_ID}).') 
        if not reinstating: time.sleep(0.25)
        console.log('Client').print(f'   $Client({self.name}): Passing request to Operating System.')
        response: Optional[MFARegistrationApproval] = operating_system.approve_mfa_registration_request(request, self)
        if response:
            console.log('Client').print(f'   $Client({self.name}): Received approval from Operating System.')
            console.log('Client').print(f'   $Client({self.name}): Passing approval to RP({talking_to.name}).')
            return response
        console.log('Client').print(f' $Client({self.name}): did not recieve approval yet ... still waiting ')
        if not reinstating: time.sleep(0.35)
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
        return Connection(self, WEBSITES[website], UI_ptr)
    
    def connected_action(self, connection: Connection, action: ConnectionAction) -> bool:
        if action == ConnectionAction.Login:
            return not not self._login_user(connection)



    def _login_user(self, connection: Connection) -> Optional[SessionToken]:
        global reinstating
        try:
            global WEBSITES
            web_name = connection.website.name
            RP = WEBSITES[web_name]
            forwarding: str = '' if RP.name == RP._pretending_to_be else f' Forwarding {RP._pretending_to_be} data to {self.name}:'
            if RP.number_of_accounts() == 0:
                console.log('Client').err(f'   $Client({self.name})::ERR: No accounts found for "{web_name}". Create an account first.')
                return None
            while True:
                console.log('Client').print(f'   $Client({self.name}): Sending login request to RP({RP.name})')
                console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Requesting Tuple(Username, Password) from Client({self.name})')
                console.log('Client').post()
                set_readline(list(connection.website.accounts.keys()))
                username = input(f'   $Client({self.name}): Enter username > {Colors.CLEAR}')
                set_readline([])
                console.log('Client').print(f'   $Client({self.name}): Enter password > {Colors.CLEAR}', end='')
                password = getpass.getpass(prompt='')
                secure_password = '*' * len(password)
                console.log('Client').print(f'   $Client({self.name}): Passing Tuple({username, secure_password}) to RP({RP.name})')
                session_token: Optional[SessionToken] = RP.grant_session_token_1FA(username, password, connection, f=forwarding)
                if not session_token: 
                    console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Username or Password incorrect. Access denied. (1FA Fail)')
                    console.log('Client').print(f'   $Client({self.name}): Recieved "HTTP 403" (Access denied) from RP({RP.name})')
                    console.log('Client').post()
                    set_readline(['yes', 'no'])
                    if input(f'   $Client({self.name}): Try again? (Y/n) > {Colors.CLEAR}').lower() in ['y', 'yes']:
                        set_readline([])
                        continue
                    set_readline([])
                    return None
                break
            console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}):{forwarding} Username and password hash match...')
            if RP.requires_2FA(username):
                console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} User="{username}@{RP.name}" requires 2FA...')
                if RP.requires_2FA(username, 'Auth App'):
                    session_token: Optional[SessionToken] = self.MFA_LOG_Auth_App(RP, forwarding, connection, username, session_token)
                elif RP.requires_2FA(username, 'OTP'):
                    session_token: Optional[SessionToken] = self.MFA_LOG_OTP(RP, forwarding, connection, username, session_token)
                elif RP.requires_2FA(username, 'FIDO-2'):
                    session_token: Optional[SessionToken] = self.MFA_LOG_FIDO2(RP, forwarding, connection, username, session_token)
                
                if not session_token:
                    console.log('Client').print(f'   $Client({self.name}): Recieved "HTML 403" as a response from RP({RP.name})')
                    return None
                console.log('Client').print(f"  $Client({self.name}): MFA login successful!")
            else:
                RP.p(f'{Colors.CLEAR}{Colors.GREEN_REVERSE}Caught Exception:{Colors.CLEAR}{Colors.GREEN} AccountExceptions.MFA_Missing(user={username}@{RP.name}){Colors.CLEAR}')
                console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}):{forwarding} User={username}@{RP.name} does not have 2FA configured -> skipping 2FA')
            console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}):{forwarding} User={username}@{RP.name} Access Granted!')
        except KeyboardInterrupt as ki:
            return None
        console.log(RP.classname).print(f'{RP.INDENT}$RP({RP.name}):{forwarding} Passing SessionToken({get_rand_id(18)}) to Client')
        return session_token

    def MFA_LOG_Auth_App(
            self, RP: RelyingParty, forwarding: str, connection: Connection, username: str, session_token: SessionToken
        ) -> Optional[SessionToken]:
        try:
            global reinstating
            client: Client = connection.client
            RP.p(f'Sending request to Client({client.name})', end='\r')
            if not reinstating: time.sleep(0.1)
            RP.p(f'Sending request to Client({client.name}) .', end='\r')
            if not reinstating: time.sleep(0.1)
            RP.p(f'Sending request to Client({client.name}) . .', end='\r')
            if not reinstating: time.sleep(0.1)
            RP.p(f'Sending request to Client({client.name}) . . .')
            if not reinstating: time.sleep(0.05)

            console.log('Client').print(f'   $Client({client.name}): Recieved request for Auth App MFA from RP({self.name})')
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System . .', end='\r')
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f'   $Client({client.name}): Requesting Auth App MFA from Operating System . . .')
            if not reinstating: time.sleep(0.05)

            console.log('OperatingSystem').print(f' $OperatingSystem: Enter the six digit code on your authenticator when prompted')
            chances: int = 3
            correct_code = False
            while chances > 0 and not correct_code:
                console.log('OperatingSystem').post()
                auth_app_OTC: str = input(f' $OperatingSystem: Enter the six digit code on your authenticator ({chances} left) > {Colors.CLEAR}')
                if QR_Code.validate_code(RP.accounts[username].public_key, auth_app_OTC):
                    correct_code = True
                chances -= 1
                self.send_code_message(RP, forwarding, connection, username, session_token, auth_app_OTC, correct_code)
            return RP.grant_session_token_MFA_using_Auth_App(username, session_token, connection) if correct_code else None
        except KeyboardInterrupt:
            return None

    def send_code_message(
            self, RP: RelyingParty, forwarding: str, connection: Connection, username: str, session_token: SessionToken, code: str, approved: bool
        ) -> None:
        console.log('OperatingSystem').print(f' $OperatingSystem: Sending "{code}" to Client({self.name})')
        console.log('Client').print(f'   $Client({self.name}): Received "{code}" from Operating System')
        console.log('Client').print(f'   $Client({self.name}): Sending "{code}" to RP({RP.name})')
        console.log('RelyingParty').print(f'     $RP({RP.name}): {forwarding} Received "{code}" from Client({self.name})')
        global cursor
        for i in range(12):
            console.log('RelyingParty').print(f'     $RP({RP.name}): {forwarding} Validating Code="{code}" for user="{username}@{RP.name}" {cursor[i%len(cursor)]}', end='\r')
            time.sleep(0.1)
        if approved:
            console.log('RelyingParty').print(f'     $RP({RP.name}): {forwarding} Validated Code="{code}" for user="{username}@{RP.name}"!  ')
        else:
            console.log('RelyingParty').print(f'     $RP({RP.name}): {forwarding} Failed to validate Code="{code}" for user="{username}@{RP.name}"!')

    def MFA_LOG_OTP(
            self, RP: RelyingParty, forwarding: str, connection: Connection, username: str, session_token: SessionToken
        ) -> Optional[SessionToken]:
        global reinstating
        client: Client = connection.client
        RP.p(f'Sending request to Client({client.name})', end='\r')
        if not reinstating: time.sleep(0.1)
        RP.p(f'Sending request to Client({client.name}) .', end='\r')
        if not reinstating: time.sleep(0.1)
        RP.p(f'Sending request to Client({client.name}) . .', end='\r')
        if not reinstating: time.sleep(0.1)
        RP.p(f'Sending request to Client({client.name}) . . .')
        if not reinstating: time.sleep(0.05)

        console.log('Client').print(f'   $Client({client.name}): Recieved request for OTP from RP({self.name})')
        console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System', end='\r')
        if not reinstating: time.sleep(0.1)
        console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System .', end='\r')
        if not reinstating: time.sleep(0.1)
        console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System . .', end='\r')
        if not reinstating: time.sleep(0.1)
        console.log('Client').print(f'   $Client({client.name}): Requesting OTP from Operating System . . .')
        if not reinstating: time.sleep(0.05)

        console.log('OperatingSystem').print(f' $OperatingSystem: Insert YubiKey into USB port')
        console.log('OperatingSystem').print(f' $OperatingSystem: Press YubiKey when prompted . . .')

        otp: Optional[str] = YubiKey.get_OTP()
        if not otp:
            console.log('OperatingSystem').print(f' $OperatingSystem: YubiKey OTP failed')
            time.sleep(0.01)
            console.log('Client').print(f'   $Client({client.name}): Failed to recieve OTP from Operating System . . .')
            time.sleep(0.01)
            RP.p(f'Did not receive OTP from Client({client.name}) in time.')
            return None
        time.sleep(0.25)
        console.log('OperatingSystem').print(f' $OperatingSystem: Sending YubiKey OTP({otp}) to Client({client.name})')
        time.sleep(0.01)
        console.log('Client').print(f'   $Client({client.name}): Received OTP({otp}) from Operating System')
        console.log('Client').print(f'   $Client({client.name}): Sending YubiKey OTP to RP({self.name})')
        time.sleep(0.01)
        RP.p(f'Received OTP({otp}) from Client({client.name})')
        RP.p(f'Validating YubiKey OTP with ID={otp[:12]}...')
        RP.p(f'Sending OTP to YubiCO for validation...')
        time.sleep(0.25)
        if not YubiKey.validate_OTP(username, RP.accounts[username].public_key, otp=otp):
            console.log('RelyingParty').print(f"    $RP({self.name}): Cryptographic backend returned an error: Excations.Cryptographic_backend.OTP_ERROR")
            global cursor
            for i in range(10):
                console.log('RelyingParty').print(f"    $RP({self.name}): Revoking SessionToken(Type=1FA) {cursor[i%len(cursor)]}", end='\r')
            console.log('RelyingParty').print(f"    $RP({self.name}): Revoked SessionToken(Type=1FA)    ")
            console.log('RelyingParty').print(f"    $RP({self.name}): MFA Failed.")
            return None
        return RP.grant_session_token_MFA_using_OTP(username, session_token, connection)

    def MFA_LOG_FIDO2(
            self, RP: RelyingParty, forwarding: str, connection: Connection, username: str, session_token: SessionToken
        ) -> Optional[SessionToken]:
        console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Sending request to client for user to insert and auth using YubiKey for the respective account...')
        if not reinstating: time.sleep(0.1)
        YK: Optional[YubiKey] = connection.request_yubikey_insert_from_OS(username)
        if not YK:
            if not reinstating: time.sleep(1.2)
            console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} User="{username}@{RP.name}" timmed out')
            console.log('Client').print(f'   $Client({self.name}): 2FA failed. Access denied.')
            return None
        challenge: Optional[Challenge] = RP.request_challenge(username, session_token, YK) # will print generating challenge
        if not challenge:
            console.log('Client').print(f'   $Client({self.name}): Waiting ...')
            if not reinstating: time.sleep(1.5)
            console.log('Client').print(f'   $Client({self.name}): Request for "challenge request" timemed out')
            if not reinstating: time.sleep(1.2)
            console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Request for "challenge request" from usr="{username}" timmed out')
            console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Sending "{username}" back to main menu')
            return None
        console.log('Client').print(f'   $Client({self.name}): Recieved challenge from RP({RP.name})')
        console.log('Client').print(f'   $Client({self.name}): Verifying source of challenge . . .')
        self.print_backend(f'Comunicating with: RP({RP.name})')
        self.print_backend(f'Challenge signed by RP({challenge.RP_ID})')
        if challenge.RP_ID != RP.name:
            self.print_backend(f'RP({RP.name}) != RP({challenge.RP_ID})')
            self.print_backend(f'THROW Exceptions.CryptographicBackend.UnknownRelyingParty')
            console.log('Client').print(f'   $Client({self.name}): {Colors.CLEAR}{Colors.BLUE_REVERSE}Caught Exception:{Colors.CLEAR}{Colors.BLUE} Exceptions.CryptographicBackend.UnknownRelyingParty')
            console.log('Client').print(f'   $Client({self.name}): Failed to varify challenge sender as ({RP.name}). Challenge originating ID does not match communicating sub-domain. ')
            space = ' ' * len(f'   $Client({self.name}): ')
            console.log('Client').print(f'{space}... ignoring challenge')
            console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} usr="{username}" timmed out')
            console.log('Client').print(f'   $Client({self.name}): 2FA failed. Access denied.')
            return None
        self.print_backend(f'RP({RP.name}) == RP({challenge.RP_ID})')
        console.log('Client').print(f'   $Client({self.name}): Successfully verified challenge sender as RP({RP.name}). Challenge originating ID matches communicating sub-domain.')
        space = ' ' * len(f'   $Client({self.name}): ')
        global cursor
        for i in range(14):
            console.log('Client').print(f'{space}... passing challenge to operating system for YubiKey authentication {cursor[i%len(cursor)]}', end='\r')
            if not reinstating: time.sleep(0.1)
        console.log('Client').print(f'{space}... passing challenge to operating system for YubiKey authentication  ')
        console.log('YubiKey').print_backend(
            f'$YK({YK.ID})',  
            '.crypto_backend.authentic:', 
            f' Recieved Challenge from Operating System on behalf of Client on behalf of RP.')
        console.log('YubiKey').print_backend(
            f'$YK({YK.ID})',  
            '.crypto_backend.authentic:', 
            f' Waiting for User to press YubiKey button to authenitcate')
        console.log('OperatingSystem').post()
        set_readline(['yes', 'no'])
        if input(f" $OperatingSystem: Press the YubiKey to authenticate? (Y/n) > {Colors.CLEAR}").lower() not in ['y', 'yes']:
            set_readline([])
            console.log('OperatingSystem').print(f' $OperatingSystem: Letting challenge time out...')
            if not reinstating: time.sleep(0.8)
            console.log('Client').print(f'   $Client({self.name}): Challenge timmed out...')
            console.log(RP.classname).print(f'     $RP({RP.name}):{forwarding} Challenge timmed out...')
            return None
        set_readline([])
        response: YubiKeyResponse = connection.request_yubikey_auth_from_OS(YK.ID, challenge)
        console.log('OperatingSystem').print(f' $OperatingSystem: Receved YubiKey authentication in the form of a signed nonce.')
        console.log('OperatingSystem').print(f' $OperatingSystem: Sending authentication to client({self.name})...')
        if not reinstating: time.sleep(0.1)
        console.log('Client').print(f"  $Client({self.name}): Recieved Yubikey auth from OS...")
        console.log('Client').print(f"  $Client({self.name}): Passing Yubikey auth to RP...")
        if not response:
            return None
        if not reinstating: time.sleep(0.1)
        return RP.grant_session_token_MFA(username, session_token, response, connection)

    def print_backend(self, message: str) -> None:
        print('       ', end='')
        console.log('Client').print_backend(f'     Client({self.name}).', 'crypto_backend.WebAuthn:     ', f" {message}")

def get_rand_id(length: int) -> str:
    return ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=length))
    
def hash(inp:str)->bytes:
    sha256_instance = sha256()
    sha256_instance.update(inp.encode('utf8'))
    return sha256_instance.digest()

def is_signed(nonce: bytes, public_key, response: bytes, RP_name: str = '') -> bool:
    """
    Verifies that the given response is a valid signature for the nonce, using the public key.
    """
    try:
        console.log('RelyingParty').print_backend(
            f'       $RP({RP_name}).', 
            'crypto_backend.AsymetricDecr:', 
            f' Trying to decrypt response="{bytes_to_base64(response)}" using public key on file {bytes_to_base64(YubiKey.public_key_to_bytes(public_key))}'
        )
        # Verify the signature using the public key
        public_key.verify(
            response,
            nonce,
            ec.ECDSA(hashes.SHA256())  # Using ECDSA with SHA-256
        )
        console.log('RelyingParty').print_backend(
            f'       $RP({RP_name}).', 
            'crypto_backend.SessionToken: ', 
            f' Decrypted response successfully'
        )
        console.log('RelyingParty').print_backend(
            f'       $RP({RP_name}).', 
            'crypto_backend.SessionToken: ', 
            f' Decrypted response is equal to nonce that was originally sent to the user'
        )
        return True
    except InvalidSignature:
        console.log('RelyingParty').print_backend(
            f'       $RP({RP_name}).', 
            'crypto_backend.SessionToken: ', 
            f' Decryption failed'
        )
        return False
    

def void(*args, **kwargs):
    pass

def changes_made() -> bool:
    global state_saved
    return not state_saved
def end_reinstating():
    global reinstating
    reinstating = False

import getpass


class RunContext(Enum):
    AUTO_DETECT = 1
    INTERACTIVE = 2


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
    return base64.urlsafe_b64encode(value).decode('utf-8')

def base64_to_bytes(base64_string: str) -> bytes:
    return base64.urlsafe_b64decode(base64_string)

__options__: list = []

def set_readline(options: list):
    global __options__
    __options__ = options
def __completer(text, state):
    global __options__
    matches = [option for option in __options__ if option.lower().startswith(text.lower())]
    if state < len(matches):
        return matches[state]
    else:
        return None
def start_compiler():
    readline.set_completer(__completer)
    readline.parse_and_bind("tab: complete")


class UserFacingConnection:
    def __init__(self, connection: Connection):
        self.connection: Connection = connection
        self.ID = get_rand_id(10)
    def execute(self, action: ConnectionAction) -> bool:
        global reinstating
        reinstating = False
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

    def __str__(self):
        return f"UserFacingConnection(self.ID)"
    def __repr__(self) -> str:
        return self.__str__()

    def available_actions(self, client: Client, rp: RelyingParty) -> List[ConnectionAction]:
        print('')
        statement: Optional[List[str]] = None if rp.name == rp._pretending_to_be else [
            f' << RP({rp.name}) establishing connection to RP({rp._pretending_to_be}) >>',
            f'    > Connection established <',
            f' << RP({rp.name}) is now forwarding everything to and from RP({rp._pretending_to_be}) >>'
        ]
        global reinstating
        if self.is_logged_in():
            console.log('Client').print(f"  $Client({client.name}): Requesting a list of legal actions from RP({rp.name})")
            if not reinstating: time.sleep(0.1)
            console.log('RelyingParty').print(f"    $RP({rp.name}): Got request from Client({client.name}) for legal actions ... returning legal actions for ConnectionType=\"logged in user={self.connection.session_token.for_account}@{self.connection.website.name}\"")
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f"  $Client({client.name}): Recieved list of legal actions from RP({rp.name}).")
        else:
            if not reinstating and statement:
                for i, s in enumerate(statement):
                    console.log('RelyingParty').print(f'     {s}')
                    if i % 2 == 0:
                         time.sleep(1)
                print('')
            console.log('Client').print(f"  $Client({client.name}): Requesting a list of legal actions from RP({rp.name})")
            if not reinstating: time.sleep(0.1)
            console.log('RelyingParty').print(f"    $RP({rp.name}): Got request from Client({client.name}) for legal actions ... returning legal actions for ConnectionType=\"not logged in\"")
            if not reinstating: time.sleep(0.1)
            console.log('Client').print(f"  $Client({client.name}): Recieved list of legal actions from RP({rp.name}).")
            
        print('')
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

class OperatingSystem:
    def __init__ (self, run_context: RunContext):
        self.console: Colors = Colors(display=(run_context == 1))
        self.clients: Dict[str, Client] = {}
        self.YubiKeys = {}

    def approve_mfa_registration_request(self, request: MFARegistrationRequest, by_client: Client) -> Optional[MFARegistrationApproval]:
        console.log('OperatingSystem').print(f" $OperatingSystem: Recieved mfa registration request from Client({by_client.name}) on behalf of RP({request.RP_ID}).")
        if len(self.YubiKeys) == 0:
            console.log('OperatingSystem').print(f" $OperatingSystem: {Colors.CLEAR}{Colors.RED_REVERSE}No YubiKeys registered on this device.{Colors.CLEAR}{Colors.RED} You do not have the ability approve this request.")
            console.log('OperatingSystem').print(f" $OperatingSystem: Registration request timmed out.")
            return None
        console.log('OperatingSystem').print(f" $OperatingSystem: Here are a list of your YubiKeys:")
        base_buff: str = ' ' * len(' $OperatingSystem:')
        for i, yk in enumerate(self.YubiKeys.keys()):
            console.log('OperatingSystem').print(f"{base_buff}\t {i + 1}. '{yk}'")
        console.log('OperatingSystem').print(f"{base_buff}\t {i + 2}. deny registration request")
        console.log('OperatingSystem').post()
        set_readline(list(self.YubiKeys.keys()))
        inp = input(f" $OperatingSystem: Please select a YubiKey to approve (or {i + 2} to deny) > {Colors.CLEAR}")
        set_readline([])
        yk_name: Optional[str] = None
        try:
            ichoice = int(inp)
            yk_name = (list(self.YubiKeys.keys()) + ['deny registration request'])[ichoice - 1]
        except ValueError:
            for yk in list(self.YubiKeys.keys()) + ['deny registration request']:
                if yk.lower().startswith(inp.lower()):
                    yk_name = yk
                    break
        if not yk_name:
            console.log('OperatingSystem').print(f" $OperatingSystem: Invalid choice '{inp}'. Registration request timmed out.")
            return None
        if yk_name == 'deny registration request':
            console.log('OperatingSystem').print(f" $OperatingSystem: Registration request denied.")
            return None
        yk: YubiKey = self.YubiKeys[yk_name]
        approval: MFARegistrationApproval = yk.register_account(request)
        console.log('OperatingSystem').print(f" $OperatingSystem: Received approved registration request from YubiKey({yk.ID}) for RP({request.RP_ID}) on behalf of user {request.username}...")
        space: str = ' ' * len(' $OperatingSystem: ')
        console.log('OperatingSystem').print(f"{space}... in the form the YubiKey({approval.YubiKeyID})'s public key (for this account): {approval.public_key}")
        console.log('OperatingSystem').print(f" $OperatingSystem: Passing approval to Client({by_client.name}).")
        return approval



    def new_YubiKey(self) -> str:
        secret = os.urandom(32)
        YK = YubiKey(secret)
        self.YubiKeys[YK.ID] = YK
        console.log('YubiKey Factory').print(f"     $YubiKey Factory: creating new YubiKey with ID = '{YK.ID}'")
        console.log('YubiKey Factory').print(f"     $YubiKey Factory: hardcoded Yubikey('{YK.ID}') with the following secret key: 64{bytes_to_base64(secret)}")
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
            console.log('OperatingSystem').print(f" $OperatingSystem: setting YubiKey({yk.ID}) and restoring old secret ...")

    def boot_client(self, client_name='Chome.exe') -> Client:
        if client_name not in self.clients.keys():
            console.log('OperatingSystem').print(f' $OperatingSystem: creating new client "{client_name}"')
            self.clients[client_name] = Client(client_name)
        else:
            console.log('OperatingSystem').print(f' $OperatingSystem: client "{client_name}" already exists, restarting client...')
        return self.clients[client_name]

    def _get_connection(self, client_name, website) -> Connection:
        if client_name not in self.clients.keys():
            console.log('OperatingSystem').print(f' $OperatingSystem: creating new client "{client_name}"')
            self.clients[client_name] = Client(client_name)
        client = self.clients[client_name]
        return client.connect(website, self)

    def connect_to_internet(self, client_name, website):
        console.log('OperatingSystem').print(f' $OperatingSystem: requesting Client({client_name}) to connect to {website}')
        return UserFacingConnection(self._get_connection(client_name, website))

    def update_backend_settings(self, display: bool):
        global console
        console.set_backend_display(display)

    def insert_yubikey(self, connection: Connection, account: str) -> Optional[YubiKey]:
        console.log('OperatingSystem').print(f' $OperatingSystem: Client({connection.client.name}) is requesting YubiKey authentication for account="{account}" on behalf of RP({connection.website.name})')
        console.log('OperatingSystem').post()
        undesided: bool = True
        while undesided:
            set_readline(['yes', 'no', 'Insert YubiKey', 'Deny Login Request'])
            resp = input(f' $OperatingSystem: Insert YubiKey or Deny Login Request (Y/n) > {Colors.CLEAR}')
            if 'Insert YubiKey'.lower().startswith(resp.lower()) or 'Deny Login Request'.lower().startswith(resp.lower()) or resp.lower() in ['y', 'yes', 'n', 'no']:
                undesided = False
                set_readline([])
        if 'Denny Login Request'.lower().startswith(resp.lower()) or resp.lower() in ['n', 'no']:
            return None
        while True:
            console.log('OperatingSystem').print(' $OperatingSystem: YubiKey IDs:')
            space = ' ' * len(' $OperatingSystem:')
            for i, id in enumerate(list(self.YubiKeys.keys())):
                console.log('OperatingSystem').print(f'{space} {i + 1}. {id}')
            selectedYubiKey: Optional[YubiKey] = None
            selectedYubiKeyName: Optional[str] = None
            try:
                set_readline(list(self.YubiKeys.keys()))
                console.log('OperatingSystem').post()
                resp = input(f' $OperatingSystem: Select YubiKey to insert > {Colors.CLEAR}')
                set_readline([])
                index = int(resp)
                if index > 0 and index <= len(self.YubiKeys.keys()):
                    selectedYubiKeyName: str = list(self.YubiKeys.keys())[index - 1]
                    selectedYubiKey = self.YubiKeys[selectedYubiKeyName]
                    self.print_spinning_cursor(selectedYubiKeyName)
                    console.log('OperatingSystem').print(f' $OperatingSystem: YubiKey({selectedYubiKeyName}) inserted into computer...')
                    return selectedYubiKey
            except ValueError:
                for yk_name in self.YubiKeys.keys():
                    if yk_name.lower().startswith(resp.lower()):
                        selectedYubiKeyName = yk_name
                        selectedYubiKey = self.YubiKeys[selectedYubiKeyName]
                        self.print_spinning_cursor(selectedYubiKeyName)
                        console.log('OperatingSystem').print(f' $OperatingSystem: YubiKey({selectedYubiKeyName}) inserted into computer...')
                        return selectedYubiKey
                set_readline(['yes', 'no'])
                console.log('OperatingSystem').post()
                if input(f' $OperatingSystem: "{resp}" out of bounds and no such key starts with ("{resp}"), try again (Y/n)? {Colors.CLEAR}').lower() in ['y', 'yes']:
                    console.clear()
                    set_readline([])
                    continue
                console.clear()
                set_readline([])
                console.log('OperatingSystem').print(f" $OperatingSystem: You didn't enter a YubiKey in time!")
                return None
    def print_spinning_cursor(self, selectedYubiKeyName: str):
        global cursor
        for i in range(18):
            console.log('OperatingSystem').print(f' $OperatingSystem: Inserting YubiKey({selectedYubiKeyName}) {cursor[i%len(cursor)]}', end='\r')
            global reinstating
            if not reinstating: time.sleep(0.15)
    # will always return bytes, may be wrong but will always return bytes (never None)
    def YubiKey_auth(self, ykID: int, challenge: Challenge) -> YubiKeyResponse:
        YK: YubiKey = self.YubiKeys[ykID]
        return YK.auth_2FA(challenge)
    
    def YKs_to_string(self):
        result: List[str] = []
        for _, yk in self.YubiKeys.items():
            result.append(f'{yk}')
        return result
    
class QR_Code:
    def __init__(self, provisioning_uri: str, username: str, issuer_name: str, secret):
        self.provisioning_uri = provisioning_uri
        self.username = username
        self.issuer_name = issuer_name
        self.secret = secret
    
    def get_secret(self):
        return self.secret
    
    def display(self, confirm:bool=True):
        self.display_on_powershell() if running_on_PowerShell() else self.display_on_bash()
        if confirm: 
            while not QR_Code.validate_code(
                self.get_secret(), 
                input('Enter the six digit code on your authenticator > ')
            ):
                print(" ! INCORRECT CODE ! \ntry again or KeyboardInterrupt\n")

    def display_on_bash(self):
        qrcode_terminal.draw(self.provisioning_uri)

    def display_on_powershell(self):
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=0,
        )
        qr.add_data(self.provisioning_uri)
        qr.make(fit=True)
        qr_matrix = qr.get_matrix()
        border_size = 4
        size_with_border = len(qr_matrix) + 2 * border_size
        bordered_matrix = [[False] * size_with_border for _ in range(size_with_border)]
        for r in range(len(qr_matrix)):
            for c in range(len(qr_matrix[r])):
                bordered_matrix[r + border_size][c + border_size] = qr_matrix[r][c]
        for row in bordered_matrix:
            line = ''.join(['██' if cell else '  ' for cell in row])
            print(line)

    @staticmethod
    def generate(username: str, issuer_name="Demo"):
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(username, issuer_name=issuer_name)
        return QR_Code(totp_uri, username, issuer_name, totp_secret)
    @staticmethod
    def validate_code(totp_secret: str, authenticator_app_code: str) -> bool:
        return pyotp.TOTP(totp_secret).verify(authenticator_app_code)
