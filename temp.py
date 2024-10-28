import sys
import os

def is_externally_managed():
    """Check if the environment is externally managed (PEP 668)."""
    # PEP 668 environments are marked by an 'EXTERNALLY-MANAGED' file
    return os.path.exists("/usr/share/python-wheels/EXTERNALLY-MANAGED") or os.path.exists("/etc/pep668/EXTERNALLY-MANAGED")

def is_running_in_virtualenv():
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

def main():
    if is_running_in_virtualenv():
        print("Running inside a Python virtual environment or externally managed environment.")
    else:
        print("Not running inside a virtual environment or an externally managed environment.")

main()