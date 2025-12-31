#!/usr/bin/env python3
import subprocess

result = subprocess.run(['python3', 'generate_full_block_indented.py'], capture_output=True, text=True)
lines = result.stdout.splitlines()
output_lines = []
for line in lines:
    # Remove any leading spaces, then add two spaces
    stripped = line.lstrip(' ')
    output_lines.append('  ' + stripped)
# Join with newline
print('\n'.join(output_lines))