/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { type Argv } from 'yargs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { homedir } from 'node:os';

/**
 * Generates shell completion scripts for different shells
 */
export const completionCommand = (yargsInstance: Argv) => {
  yargsInstance.command(
    'completion [shell]',
    'Generate shell completion scripts',
    (yargs) =>
      yargs
        .positional('shell', {
          describe: 'Shell type (bash, zsh, fish)',
          type: 'string',
          choices: ['bash', 'zsh', 'fish'],
          default: detectShell(),
        })
        .option('install', {
          alias: 'i',
          type: 'boolean',
          description: 'Install the completion script automatically',
          default: false,
        })
        .option('output', {
          alias: 'o',
          type: 'string',
          description: 'Output file path (if not using --install)',
        }),
    async (argv) => {
      const shell = argv.shell as 'bash' | 'zsh' | 'fish';
      const install = argv.install as boolean;
      const outputPath = argv.output as string | undefined;

      try {
        const script = generateCompletionScript(shell);

        if (install) {
          await installCompletion(shell, script);
        } else if (outputPath) {
          await fs.writeFile(outputPath, script, 'utf-8');
          console.log(`✅ Completion script written to: ${outputPath}`);
          console.log(`\nTo enable completions, add the following to your shell config:`);
          printInstallInstructions(shell, outputPath);
        } else {
          // Print to stdout
          console.log(script);
        }
      } catch (error) {
        console.error(`❌ Error generating completion script:`, error);
        process.exit(1);
      }
    },
  );
};

/**
 * Detects the current shell from environment
 */
function detectShell(): 'bash' | 'zsh' | 'fish' {
  const shell = process.env['SHELL'] || '';
  if (shell.includes('zsh')) return 'zsh';
  if (shell.includes('fish')) return 'fish';
  return 'bash';
}

/**
 * Generates completion script for the specified shell
 */
function generateCompletionScript(shell: 'bash' | 'zsh' | 'fish'): string {
  switch (shell) {
    case 'bash':
      return generateBashCompletion();
    case 'zsh':
      return generateZshCompletion();
    case 'fish':
      return generateFishCompletion();
  }
}

/**
 * Generates Bash completion script
 */
function generateBashCompletion(): string {
  return `#!/usr/bin/env bash
# DarkCoder bash completion script
# Generated on ${new Date().toISOString()}

_darkcoder_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]}"

    # Main options and commands
    opts="--help --version --debug --model --prompt --yolo --approval-mode --telemetry \\
          --sandbox --all-files --continue --resume --config --proxy \\
          --input-format --output-format completion extensions mcp"

    # Subcommands
    local extensions_cmds="list install uninstall enable disable update new link"
    local mcp_cmds="list add remove"

    # If previous word is darkcoder, show main options
    if [ "\${COMP_CWORD}" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "\${opts}" -- \${cur}) )
        return 0
    fi

    # Handle subcommands
    case "\${COMP_WORDS[1]}" in
        extensions)
            if [ "\${COMP_CWORD}" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "\${extensions_cmds}" -- \${cur}) )
            fi
            ;;
        mcp)
            if [ "\${COMP_CWORD}" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "\${mcp_cmds}" -- \${cur}) )
            fi
            ;;
        completion)
            if [ "\${COMP_CWORD}" -eq 2 ]; then
                COMPREPLY=( $(compgen -W "bash zsh fish" -- \${cur}) )
            fi
            ;;
    esac

    # Handle option arguments
    case "\${prev}" in
        --model|-m)
            # Suggest common models
            local models="gpt-4o gpt-4o-mini claude-3-5-sonnet claude-3-5-haiku qwen-coder-plus gemini-2.0-flash-exp"
            COMPREPLY=( $(compgen -W "\${models}" -- \${cur}) )
            ;;
        --approval-mode)
            COMPREPLY=( $(compgen -W "plan default auto-edit yolo" -- \${cur}) )
            ;;
        --input-format)
            COMPREPLY=( $(compgen -W "text multimodal" -- \${cur}) )
            ;;
        --output-format)
            COMPREPLY=( $(compgen -W "text json stream-json" -- \${cur}) )
            ;;
        --sandbox)
            COMPREPLY=( $(compgen -W "docker podman false" -- \${cur}) )
            ;;
        --config)
            # Complete file paths
            COMPREPLY=( $(compgen -f -- \${cur}) )
            ;;
    esac

    return 0
}

complete -F _darkcoder_completions darkcoder
`;
}

/**
 * Generates Zsh completion script
 */
function generateZshCompletion(): string {
  return `#compdef darkcoder
# DarkCoder zsh completion script
# Generated on ${new Date().toISOString()}

_darkcoder() {
    local -a commands options

    commands=(
        'completion:Generate shell completion scripts'
        'extensions:Manage extensions'
        'mcp:Manage MCP servers'
    )

    options=(
        '(-h --help)'{-h,--help}'[Show help]'
        '(-v --version)'{-v,--version}'[Show version]'
        '(-d --debug)'{-d,--debug}'[Run in debug mode]'
        '(-m --model)'{-m,--model}'[Specify AI model]:model:(gpt-4o gpt-4o-mini claude-3-5-sonnet claude-3-5-haiku qwen-coder-plus gemini-2.0-flash-exp)'
        '(-p --prompt)'{-p,--prompt}'[Non-interactive prompt]:prompt'
        '--yolo[Auto-approve all operations]'
        '--approval-mode[Set approval mode]:mode:(plan default auto-edit yolo)'
        '--sandbox[Enable sandbox mode]:mode:(docker podman false)'
        '--all-files[Include all files in context]'
        '--continue[Resume most recent session]'
        '--resume[Resume specific session]:session-id'
        '--config[Configuration file path]:file:_files'
        '--proxy[HTTP proxy URL]:url'
        '--input-format[Input format]:format:(text multimodal)'
        '--output-format[Output format]:format:(text json stream-json)'
        '--telemetry[Enable telemetry]'
    )

    _arguments -C \\
        '\${options[@]}' \\
        '1: :->command' \\
        '*:: :->args'

    case \$state in
        command)
            _describe 'command' commands
            ;;
        args)
            case \$words[1] in
                extensions)
                    _darkcoder_extensions
                    ;;
                mcp)
                    _darkcoder_mcp
                    ;;
                completion)
                    _darkcoder_completion
                    ;;
            esac
            ;;
    esac
}

_darkcoder_extensions() {
    local -a subcommands
    subcommands=(
        'list:List all extensions'
        'install:Install an extension'
        'uninstall:Uninstall an extension'
        'enable:Enable an extension'
        'disable:Disable an extension'
        'update:Update extensions'
        'new:Create new extension'
        'link:Link local extension'
    )
    _describe 'extensions command' subcommands
}

_darkcoder_mcp() {
    local -a subcommands
    subcommands=(
        'list:List MCP servers'
        'add:Add MCP server'
        'remove:Remove MCP server'
    )
    _describe 'mcp command' subcommands
}

_darkcoder_completion() {
    local -a shells
    shells=(
        'bash:Bash completion script'
        'zsh:Zsh completion script'
        'fish:Fish completion script'
    )
    _describe 'shell' shells
}

_darkcoder "\$@"
`;
}

/**
 * Generates Fish completion script
 */
function generateFishCompletion(): string {
  return `# DarkCoder fish completion script
# Generated on ${new Date().toISOString()}

# Main commands
complete -c darkcoder -f -a "completion" -d "Generate shell completion scripts"
complete -c darkcoder -f -a "extensions" -d "Manage extensions"
complete -c darkcoder -f -a "mcp" -d "Manage MCP servers"

# Global options
complete -c darkcoder -s h -l help -d "Show help"
complete -c darkcoder -s v -l version -d "Show version"
complete -c darkcoder -s d -l debug -d "Run in debug mode"
complete -c darkcoder -s m -l model -d "Specify AI model" -x
complete -c darkcoder -s p -l prompt -d "Non-interactive prompt" -x
complete -c darkcoder -l yolo -d "Auto-approve all operations"
complete -c darkcoder -l approval-mode -d "Set approval mode" -xa "plan default auto-edit yolo"
complete -c darkcoder -l sandbox -d "Enable sandbox mode" -xa "docker podman false"
complete -c darkcoder -l all-files -d "Include all files in context"
complete -c darkcoder -l continue -d "Resume most recent session"
complete -c darkcoder -l resume -d "Resume specific session" -x
complete -c darkcoder -l config -d "Configuration file path" -r
complete -c darkcoder -l proxy -d "HTTP proxy URL" -x
complete -c darkcoder -l input-format -d "Input format" -xa "text multimodal"
complete -c darkcoder -l output-format -d "Output format" -xa "text json stream-json"
complete -c darkcoder -l telemetry -d "Enable telemetry"

# Model suggestions
complete -c darkcoder -s m -l model -xa "gpt-4o gpt-4o-mini claude-3-5-sonnet claude-3-5-haiku qwen-coder-plus gemini-2.0-flash-exp deepseek-v3 deepseek-r1"

# Extensions subcommands
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "list" -d "List all extensions"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "install" -d "Install an extension"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "uninstall" -d "Uninstall an extension"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "enable" -d "Enable an extension"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "disable" -d "Disable an extension"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "update" -d "Update extensions"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "new" -d "Create new extension"
complete -c darkcoder -n "__fish_seen_subcommand_from extensions" -a "link" -d "Link local extension"

# MCP subcommands
complete -c darkcoder -n "__fish_seen_subcommand_from mcp" -a "list" -d "List MCP servers"
complete -c darkcoder -n "__fish_seen_subcommand_from mcp" -a "add" -d "Add MCP server"
complete -c darkcoder -n "__fish_seen_subcommand_from mcp" -a "remove" -d "Remove MCP server"

# Completion subcommands
complete -c darkcoder -n "__fish_seen_subcommand_from completion" -a "bash" -d "Bash completion script"
complete -c darkcoder -n "__fish_seen_subcommand_from completion" -a "zsh" -d "Zsh completion script"
complete -c darkcoder -n "__fish_seen_subcommand_from completion" -a "fish" -d "Fish completion script"
`;
}

/**
 * Installs the completion script to the appropriate location
 */
async function installCompletion(
  shell: 'bash' | 'zsh' | 'fish',
  script: string,
): Promise<void> {
  const home = homedir();
  let installPath: string;
  let rcFile: string;

  switch (shell) {
    case 'bash':
      installPath = path.join(
        home,
        '.local',
        'share',
        'bash-completion',
        'completions',
        'darkcoder',
      );
      rcFile = path.join(home, '.bashrc');
      break;
    case 'zsh':
      installPath = path.join(home, '.zsh', 'completions', '_darkcoder');
      rcFile = path.join(home, '.zshrc');
      break;
    case 'fish':
      installPath = path.join(
        home,
        '.config',
        'fish',
        'completions',
        'darkcoder.fish',
      );
      rcFile = ''; // Fish auto-loads from completions dir
      break;
  }

  // Create directory if it doesn't exist
  await fs.mkdir(path.dirname(installPath), { recursive: true });

  // Write completion script
  await fs.writeFile(installPath, script, { mode: 0o755 });

  console.log(`✅ Completion script installed to: ${installPath}`);

  // Provide instructions
  if (shell === 'zsh') {
    console.log(`\n📝 Add this line to your ${rcFile}:`);
    console.log(`   fpath=(~/.zsh/completions $fpath)`);
    console.log(`   autoload -Uz compinit && compinit`);
  } else if (shell === 'bash') {
    console.log(`\n📝 The completion should work automatically.`);
    console.log(`   If not, add this to your ${rcFile}:`);
    console.log(`   source ${installPath}`);
  } else {
    console.log(
      `\n📝 Fish completions are automatically loaded from ~/.config/fish/completions/`,
    );
  }

  console.log(`\n🔄 Restart your shell or run: source ${rcFile || '~/.config/fish/config.fish'}`);
}

/**
 * Prints installation instructions for manual setup
 */
function printInstallInstructions(
  shell: 'bash' | 'zsh' | 'fish',
  scriptPath: string,
): void {
  switch (shell) {
    case 'bash':
      console.log(`\n  # Bash`);
      console.log(`  echo "source ${scriptPath}" >> ~/.bashrc`);
      console.log(`  source ~/.bashrc`);
      break;
    case 'zsh':
      console.log(`\n  # Zsh`);
      console.log(`  mkdir -p ~/.zsh/completions`);
      console.log(`  cp ${scriptPath} ~/.zsh/completions/_darkcoder`);
      console.log(`  echo "fpath=(~/.zsh/completions \\$fpath)" >> ~/.zshrc`);
      console.log(`  echo "autoload -Uz compinit && compinit" >> ~/.zshrc`);
      console.log(`  source ~/.zshrc`);
      break;
    case 'fish':
      console.log(`\n  # Fish`);
      console.log(`  mkdir -p ~/.config/fish/completions`);
      console.log(`  cp ${scriptPath} ~/.config/fish/completions/darkcoder.fish`);
      console.log(`  # Fish will auto-load it`);
      break;
  }
}
