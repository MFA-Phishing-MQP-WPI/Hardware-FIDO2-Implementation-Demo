# from util import YubiKey, is_signed, RelyingParty
from util import UserInterface, RunContext
import os

def main():
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
    ui: UserInterface = UserInterface(RunContext.AUTO_DETECT)
    ykID: str = ui.new_YubiKey()
    print(f'{ykID=}')


if __name__ == "__main__":
    main()
