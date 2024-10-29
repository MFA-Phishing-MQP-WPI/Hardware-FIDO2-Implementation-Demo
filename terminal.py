import os
import sys
import platform
import sysconfig
import subprocess

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
def is_externally_managed():
    """Check if the environment is externally managed by attempting a pip install and checking for the externally-managed-environment error."""
    try:
        # Attempt a harmless `pip install` with a non-existent package to trigger environment check
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--dry-run", "nonexistent-package"],
            capture_output=True,
            text=True
        )
        # Check for the specific error message in the output
        return "externally-managed-environment" in result.stderr
    except Exception as e:
        # print(f"Error checking for externally managed environment: {e}")
        return False

def is_running_in_VM():
    """
    Determine if the script is running in a Python virtual environment
    or in an externally managed system environment.
    """
    # Check for Python virtual environment
    in_virtualenv = (hasattr(sys, 'real_prefix') or
                     (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))

    # Check if the environment is externally managed
    if is_externally_managed():
        return True

    # Return True only if we're actually in a virtual environment or managed system
    return in_virtualenv

def is_running_in_virtualenv():
    """
    Determine if the script is running in a Python virtual environment
    or in an externally managed system environment.
    """
    # Check for Python virtual environment
    in_virtualenv = (hasattr(sys, 'real_prefix') or
                     (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix))
    return in_virtualenv
