import pkg_resources
import os
import subprocess
from display import COLOR_CODES
from terminal import running_on_PowerShell, is_running_on_mac, is_externally_managed
def unpack():
    print(f'{COLOR_CODES.CLIENT_LOG} <<< PACKAGE MANAGER :: VERIFYING ALL REQUIRED PACKAGES >>>{COLOR_CODES.RESET}', end='\r')
    installed_packages = [package.key for package in pkg_resources.working_set]
    required_packages = [
        'argon2-cffi', 'cryptography', 'colorama', 'readline', 'yubico-client', 'pyotp', 'qrcode', 'pillow', 'qrcode-terminal', 'qrcode'
    ] if not running_on_PowerShell() else [
        'argon2-cffi', 'cryptography', 'colorama', 'pyreadline', 'yubico-client', 'pyotp', 'qrcode', 'pillow', 'qrcode-terminal', 'qrcode'
    ]

    install_command = ['python3', '-m', 'pip', 'install']  # Default command for Linux/Windows
    
    # Detect macOS environment
    if is_running_on_mac():  
        install_command = ['python3', '-m', 'venv', 'install']  # Modify command for macOS if needed
    
    # Check if the environment is externally managed
    if is_externally_managed():
        # Recommend virtual environment creation
        print(f"\n\t{COLOR_CODES.ERROR}This is an externally managed environment.{COLOR_CODES.RESET}")
        print(f"\t{COLOR_CODES.WARNING}Creating and using a virtual environment is recommended.{COLOR_CODES.RESET}")
        
        # Check if 'venv' module is available
        if not shutil.which("python3 -m venv"):
            print(f"\t{COLOR_CODES.ERROR}The python3-venv package is missing. Install it with:{COLOR_CODES.RESET}")
            print("\tsudo apt install python3-venv")
            sys.exit(1)  # Exit the script if venv is not installed
        
        venv_dir = os.path.join(os.getcwd(), 'venv')
        if not os.path.exists(venv_dir):
            print(f"\t{COLOR_CODES.CLIENT_LOG}Creating virtual environment...{COLOR_CODES.RESET}")
            try:
                subprocess.run(['python3', '-m', 'venv', venv_dir], check=True)
            except subprocess.CalledProcessError as e:
                print(f"{COLOR_CODES.ERROR}Failed to create virtual environment: {e}{COLOR_CODES.RESET}")
                print("Please install the `python3-venv` package and try again.")
                sys.exit(1)
        
        print(f"\t{COLOR_CODES.CLIENT_LOG}Activating virtual environment...{COLOR_CODES.RESET}")
        activate_venv = os.path.join(venv_dir, 'bin', 'activate')
        os.system(f"source {activate_venv}")
        
        install_command = [os.path.join(venv_dir, 'bin', 'python'), '-m', 'pip', 'install']
    
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
