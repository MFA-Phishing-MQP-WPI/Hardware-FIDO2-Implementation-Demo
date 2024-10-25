import os
import platform
import sysconfig

running_shell = None
mycheck='/usr/bin/md5sum'

def running_on_shell() -> str: 
    if not os.path.isfile(mycheck):
        return 'PowerShell'
    else:
        return 'Bash'
def running_on_PowerShell() -> bool:
    return running_on_shell() == 'PowerShell'
def is_running_on_mac() -> bool:
    return platform.system() == 'Darwin'
def is_externally_managed() -> bool:
    try:
        extern_managed = sysconfig.get_config_var('PYTHONFRAMEWORK') is None
        return True
    except Exception as e:
        print(f"Error detecting system management: {e}")
        return False
