#!/usr/bin/env python3
import json

with open('old_mcp_section.txt', 'r') as f:
    old_string = f.read()

with open('new_mcp_section_complete.txt', 'r') as f:
    new_string = f.read()

print("Old string length:", len(old_string))
print("New string length:", len(new_string))

# Check first 200 chars of old string
print("\nOld string first 200 chars (repr):")
print(repr(old_string[:200]))

print("\nNew string first 200 chars (repr):")
print(repr(new_string[:200]))

# Check if old string exists in the main file
with open('expert-ai-system-prompt.md', 'r') as f:
    content = f.read()
    
if old_string in content:
    print("\n✓ Old string found at position:", content.find(old_string))
else:
    print("\n✗ Old string not found exactly")
    # Try to find with some flexibility
    import difflib
    # Find close matches
    for i in range(0, len(content) - len(old_string), 10000):
        substring = content[i:i+len(old_string)]
        if len(substring) < len(old_string):
            break
        similarity = difflib.SequenceMatcher(None, old_string, substring).ratio()
        if similarity > 0.9:
            print(f"  Close match at position {i} with similarity {similarity:.3f}")
            # Show difference
            diff = list(difflib.unified_diff(old_string.splitlines(), substring.splitlines(), lineterm=''))
            print("  First 5 diff lines:", diff[:5])
            break

# Write to files for manual inspection
with open('old_string_escaped.txt', 'w') as f:
    f.write(json.dumps(old_string))

with open('new_string_escaped.txt', 'w') as f:
    f.write(json.dumps(new_string))

print("\nEscaped strings written to files.")