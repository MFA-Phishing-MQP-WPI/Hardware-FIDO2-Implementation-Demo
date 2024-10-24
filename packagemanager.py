import pkg_resources
import subprocess
from display import COLOR_CODES
from terminal import running_on_PowerShell, is_running_on_mac
def unpack():
    print(f'{COLOR_CODES.CLIENT_LOG} <<< PACKAGE MANAGER :: VERIFYING ALL REQUIRED PACKAGES >>>{COLOR_CODES.RESET}', end='\r')
    installed_packages = [package.key for package in pkg_resources.working_set]
    required_packages = [
        'argon2-cffi', 'cryptography', 'colorama', 'readline', 'yubico-client', 'pyotp', 'qrcode', 'pillow', 'qrcode-terminal', 'qrcode'
    ] if not running_on_PowerShell() else [
        'argon2-cffi', 'cryptography', 'colorama', 'pyreadline', 'yubico-client', 'pyotp', 'qrcode', 'pillow', 'qrcode-terminal', 'qrcode'
    ]

    install_command = ['python3', '-m', 'pip', 'install']  # Default command for Linux/Windows
    
    if is_running_on_mac():  # If running on macOS, modify the installation command to use `venv`
        install_command = [python_executable, '-m', 'venv', 'install']
    
    for required_package in required_packages:
        if required_package not in installed_packages:
            print(f'\n\t{COLOR_CODES.CLIENT_LOG}{required_package} not installed. Installing...{COLOR_CODES.RESET}')
            try:
                result = subprocess.run(install_command + [required_package], check=True)
                # result = subprocess.run(
                #     ['python3', '-m', 'pip', 'install', required_package], #['pip', 'install', required_package] if required_package != 'colorama' else ['python3', '-m', 'pip', 'install', 'colorama'], 
                #     check=True)
                if result.returncode == 0:
                    print(f'\t{COLOR_CODES.OK}{required_package} installed successfully.{COLOR_CODES.RESET}\n')
                else:
                    print(f'\t{COLOR_CODES.ERROR}Failed to install "{required_package}"{COLOR_CODES.RESET}  - maybe try pip install {required_package}?')
            except pkg_resources.DistributionNotFound:
                raise Exception(f'\t{COLOR_CODES.ERROR_HEADER}Unable to install "{required_package}"{COLOR_CODES.RESET}')
    print(' ' * len(' <<< PACKAGE MANAGER :: VERIFYING ALL REQUIRED PACKAGES >>>'))


unpack()
