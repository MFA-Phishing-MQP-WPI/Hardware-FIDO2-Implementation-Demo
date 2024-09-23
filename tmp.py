from util import Hasher

h = Hasher('password')
H = Hasher.from_hash_string(f'{h}')
open('dump', 'w').write(f'{h}\n{H}')

if h.is_same_password(input('password: ')):
    print('Same password!')
else:
    print('Dif password!')

if Hasher.is_correct_password(input('password: '), f'{h}'):
    print('Correct password!')
else:
    print('Incorrect password!')