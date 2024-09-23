import os

files_rmeoved: int = 0

print('Removing ...')

for file in os.listdir():
    if file.endswith(".dump"):
        os.remove(file)
        print(f"\t'{file}'")
        files_rmeoved += 1

if files_rmeoved > 0:
    print(f'Removed {files_rmeoved} files')
else:
    print('Nothing to remove')