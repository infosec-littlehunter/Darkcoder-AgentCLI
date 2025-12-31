#!/usr/bin/env python3
import subprocess

# Run the indented block generator and capture output
result = subprocess.run(['python3', 'generate_full_block_indented.py'], capture_output=True, text=True)
output = result.stdout

# Ensure each line starts with two spaces (some lines may already have them)
lines = output.splitlines()
final_lines = []
for line in lines:
    # If line doesn't start with two spaces, add them
    if not line.startswith('  '):
        line = '  ' + line
    final_lines.append(line)

# Add an empty line before decision tree? Already included in decision_flow variable
# Print final block
print('\n'.join(final_lines))