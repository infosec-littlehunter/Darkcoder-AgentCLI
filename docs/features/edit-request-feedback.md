# Edit Request with Feedback

The **Edit Request with Feedback** feature allows you to provide guidance to the AI when you want it to modify its approach during tool confirmation dialogs. Instead of simply canceling a tool operation, you can provide specific instructions that help the AI understand what you want differently.

## Overview

When DarkCoder presents a tool confirmation dialog (e.g., for running a shell command, editing a file, or fetching a URL), you now have the option to:

1. **Approve** the operation (`Yes, allow once` or `Allow always`)
2. **Cancel** the operation (`No`)
3. **Edit request** - Provide feedback to guide the AI

The **Edit request** option is particularly useful when:

- The AI's approach is close but needs minor adjustments
- You want to suggest an alternative method
- You need to provide additional context
- You want to redirect the AI without starting over

## How to Use

### Step 1: Tool Confirmation Dialog

When DarkCoder requests permission to execute a tool, you'll see options like:

```
╭─────────────────────────────────────────────────────────────────╮
│ Fetch: Fetching content from https://example.com                │
╰─────────────────────────────────────────────────────────────────╯

Do you want to proceed?
  ● Yes, allow once
  ○ Allow always
  ○ Edit request (add feedback)
  ○ No
```

### Step 2: Select "Edit request"

Use the arrow keys to navigate to **"Edit request (add feedback)"** and press Enter.

### Step 3: Type Your Feedback

A text input field will appear where you can type your guidance:

```
Enter feedback for the AI:
> Use curl instead for this request
```

### Step 4: Submit

Press Enter to submit your feedback. The AI will receive your guidance along with the cancellation message and will adjust its approach accordingly.

## Example Use Cases

### Security Testing Redirection

```
AI wants to run: nmap -sS target.com

Your feedback: "Use a stealth scan with service detection instead: nmap -sS -sV --script=vuln target.com"
```

### Changing Approach

```
AI wants to fetch: https://api.target.com/users

Your feedback: "Skip the API and look for the information in the JavaScript files we already downloaded"
```

### Providing Context

```
AI wants to write file: /tmp/exploit.py

Your feedback: "Write to the project's exploits/ directory instead, and add proper error handling"
```

### Efficiency Improvements

```
AI wants to run: find / -name "*.conf"

Your feedback: "Too broad - search only in /etc and /var for configuration files"
```

## Technical Details

When you provide feedback via "Edit request":

1. The tool operation is cancelled
2. Your feedback is sent to the AI as: `[Operation Cancelled] Reason: <your feedback>`
3. The AI continues the conversation with your guidance in context
4. The AI will typically acknowledge your feedback and propose a new approach

## Keyboard Shortcuts

| Action           | Shortcut                |
| ---------------- | ----------------------- |
| Navigate options | `↑` / `↓` or `j` / `k`  |
| Select option    | `Enter`                 |
| Cancel edit mode | `Esc`                   |
| Submit feedback  | `Enter` (in text input) |

## Comparison with Other Options

| Option              | When to Use                                          |
| ------------------- | ---------------------------------------------------- |
| **Yes, allow once** | Approve this specific operation                      |
| **Allow always**    | Trust this tool/operation for the session            |
| **Edit request**    | Redirect the AI with specific guidance               |
| **No**              | Cancel without feedback (AI may retry same approach) |

## Notes

- Feedback is most effective when specific and actionable
- The AI will see your feedback and typically adjust immediately
- You can use this feature multiple times in a session
- Works with all tool types (shell commands, file operations, web fetches, etc.)
