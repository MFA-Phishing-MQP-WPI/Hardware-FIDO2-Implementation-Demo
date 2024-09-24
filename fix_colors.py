from terminal import running_on_PowerShell
if running_on_PowerShell():
    import pkg_resources
    import subprocess
    if 'colorama' not in [package.key for package in pkg_resources.working_set]:
        print('>> package::colorama is required for colors')
        result = subprocess.run(
            ['python3', '-m', 'pip', 'install', 'colorama'],
            check=True)
        if result.returncode == 0:
            print(f'\tInstalled colorama successfully.\n')
        else:
            print(f'\tFailed to install "colorama".\n')
            exit(1)
    from colorama import just_fix_windows_console
    just_fix_windows_console()