#!/usr/bin/env python3

import sys

# Read the complete new section
with open('new_mcp_section_complete.txt', 'r') as f:
    new_section = f.read()

# Read the entire file
with open('expert-ai-system-prompt.md', 'r') as f:
    content = f.read()

# Find start of MCP-Based Tool Orchestration section
start_marker = '### MCP-Based Tool Orchestration'
start_idx = content.find(start_marker)
if start_idx == -1:
    print("ERROR: Could not find start marker")
    sys.exit(1)

print(f"Found start marker at position: {start_idx}")

# Find start of Predictive Automation Framework section
end_marker = '### Predictive Automation Framework'
# Search from start_idx to avoid finding earlier occurrences
end_idx = content.find(end_marker, start_idx)
if end_idx == -1:
    print("ERROR: Could not find end marker")
    sys.exit(1)

print(f"Found end marker at position: {end_idx}")

# Check what's between start and end
current_section = content[start_idx:end_idx]
print(f"Current section length: {len(current_section)}")
print(f"Current section first 200 chars:\n{current_section[:200]}")
print(f"Current section last 200 chars:\n{current_section[-200:]}")

# New section length
print(f"New section length: {len(new_section)}")

# Perform replacement
new_content = content[:start_idx] + new_section + content[end_idx:]

# Write back
with open('expert-ai-system-prompt.md', 'w') as f:
    f.write(new_content)

print(f"Replacement complete. File updated.")
print(f"Old section size: {len(current_section)}")
print(f"New section size: {len(new_section)}")
print(f"Size change: {len(new_section) - len(current_section)} bytes")