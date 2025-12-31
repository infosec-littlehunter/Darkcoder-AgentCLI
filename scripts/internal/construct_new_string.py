#!/usr/bin/env python3

# Read first part (lines 1-150)
with open('new_mcp_section_complete.txt', 'r') as f:
    lines = f.readlines()

# Combine all lines
new_string = ''.join(lines)

print("=== NEW STRING (first 500 chars) ===")
print(new_string[:500])
print("\n=== NEW STRING (last 500 chars) ===")
print(new_string[-500:])
print("\n=== LENGTH ===")
print(len(new_string))

# Also read old string
with open('old_mcp_section.txt', 'r') as f:
    old_string = f.read()

print("\n=== OLD STRING LENGTH ===")
print(len(old_string))

# Check if old string exists in file
with open('expert-ai-system-prompt.md', 'r') as f:
    content = f.read()
    
if old_string in content:
    print("\n✓ Old string found in file")
else:
    print("\n✗ Old string NOT found in file - may have formatting differences")
    # Try to find a substring
    for i in range(0, len(old_string), 100):
        substring = old_string[i:i+100]
        if substring in content:
            print(f"  Found substring at position {i}")
            break