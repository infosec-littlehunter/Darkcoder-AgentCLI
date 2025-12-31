#!/usr/bin/env python3

import sys

def extract_section(filename, start_line, end_line):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    # Adjust for 0-based indexing
    start_idx = start_line - 1
    end_idx = end_line
    
    section = ''.join(lines[start_idx:end_idx])
    return section

if __name__ == "__main__":
    filename = "/home/littlebird/RepoTools/AssistanceAntiCyber-Darkcoder-CLI/expert-ai-system-prompt.md"
    # From grep: "### MCP-Based Tool Orchestration" is at line 6797
    # "### Predictive Automation Framework" is at line 6892
    # We want from line 6797 to line 6891 (inclusive)
    start_line = 6797
    end_line = 6891  # Exclusive
    
    old_section = extract_section(filename, start_line, end_line)
    print("OLD SECTION LENGTH:", len(old_section))
    print("OLD SECTION FIRST 500 chars:")
    print(old_section[:500])
    print("\nOLD SECTION LAST 500 chars:")
    print(old_section[-500:])
    
    # Save to file
    with open("old_mcp_section.txt", "w") as f:
        f.write(old_section)