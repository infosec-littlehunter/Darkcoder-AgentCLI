#!/usr/bin/env python3
import subprocess

result = subprocess.run(['python3', 'ensure_spaces.py'], capture_output=True, text=True)
new_string = result.stdout
print(new_string, end='')