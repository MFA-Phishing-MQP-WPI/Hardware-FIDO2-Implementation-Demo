import sys
import subprocess

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
        print(f"Error checking for externally managed environment: {e}")
        return False

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
