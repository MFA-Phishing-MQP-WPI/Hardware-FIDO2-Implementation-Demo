import os

files_rmeoved: int = 0

for file in os.listdir():
    if file.endswith(".dump"):
        os.remove(file)
        print(f"Removed {file}")
        files_rmeoved += 1

if files_rmeoved > 0:
    print(f'Removed {files_rmeoved} files')
else:
    print('Nothing to remove')