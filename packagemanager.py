import pkg_resources
import os
def unpack():
    installed_packages = [package.key for package in pkg_resources.working_set]
    required_packages = ['argon2-cffi', 'cryptography']
    for required_package in required_packages:
        if required_package not in installed_packages:
            print(f'\n{required_package} not installed. Installing...')
            try:
                os.execvp('pip', ['pip', 'install', required_package])
                print(f'{required_package} installed successfully.\n')
            except pkg_resources.DistributionNotFound:
                raise Exception(f'Unable to install {required_package}')



unpack()