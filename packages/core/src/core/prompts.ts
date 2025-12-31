/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { ToolNames } from '../tools/tool-names.js';
import process from 'node:process';
import { QWEN_CONFIG_DIR } from '../tools/memoryTool.js';
import type { GenerateContentConfig } from '@google/genai';
import type { ToolRegistry } from '../tools/tool-registry.js';
import type { DiscoveredMCPTool } from '../tools/mcp-tool.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function resolvePathFromEnv(envVar?: string): {
  isSwitch: boolean;
  value: string | null;
  isDisabled: boolean;
} {
  // Handle the case where the environment variable is not set, empty, or just whitespace.
  const trimmedEnvVar = envVar?.trim();
  if (!trimmedEnvVar) {
    return { isSwitch: false, value: null, isDisabled: false };
  }

  const lowerEnvVar = trimmedEnvVar.toLowerCase();
  // Check if the input is a common boolean-like string.
  if (['0', 'false', '1', 'true'].includes(lowerEnvVar)) {
    // If so, identify it as a "switch" and return its value.
    const isDisabled = ['0', 'false'].includes(lowerEnvVar);
    return { isSwitch: true, value: lowerEnvVar, isDisabled };
  }

  // If it's not a switch, treat it as a potential file path.
  let customPath = trimmedEnvVar;

  // Safely expand the tilde (~) character to the user's home directory.
  if (customPath.startsWith('~/') || customPath === '~') {
    try {
      const home = os.homedir(); // This is the call that can throw an error.
      if (customPath === '~') {
        customPath = home;
      } else {
        customPath = path.join(home, customPath.slice(2));
      }
    } catch (error) {
      // If os.homedir() fails, we catch the error instead of crashing.
      console.warn(
        `Could not resolve home directory for path: ${trimmedEnvVar}`,
        error,
      );
      // Return null to indicate the path resolution failed.
      return { isSwitch: false, value: null, isDisabled: false };
    }
  }

  // Return it as a non-switch with the fully resolved absolute path.
  return {
    isSwitch: false,
    value: path.resolve(customPath),
    isDisabled: false,
  };
}

/**
 * Processes a custom system instruction by appending user memory if available.
 * This function should only be used when there is actually a custom instruction.
 *
 * @param customInstruction - Custom system instruction (ContentUnion from @google/genai)
 * @param userMemory - User memory to append
 * @returns Processed custom system instruction with user memory appended
 */
export function getCustomSystemPrompt(
  customInstruction: GenerateContentConfig['systemInstruction'],
  userMemory?: string,
): string {
  // Extract text from custom instruction
  let instructionText = '';

  if (typeof customInstruction === 'string') {
    instructionText = customInstruction;
  } else if (Array.isArray(customInstruction)) {
    // PartUnion[]
    instructionText = customInstruction
      .map((part) => (typeof part === 'string' ? part : part.text || ''))
      .join('');
  } else if (customInstruction && 'parts' in customInstruction) {
    // Content
    instructionText =
      customInstruction.parts
        ?.map((part) => (typeof part === 'string' ? part : part.text || ''))
        .join('') || '';
  } else if (customInstruction && 'text' in customInstruction) {
    // PartUnion (single part)
    instructionText = customInstruction.text || '';
  }

  // Append user memory using the same pattern as getCoreSystemPrompt
  const memorySuffix =
    userMemory && userMemory.trim().length > 0
      ? `\n\n---\n\n${userMemory.trim()}`
      : '';

  return `${instructionText}${memorySuffix}`;
}

export interface SystemPromptOptions {
  userMemory?: string;
  model?: string;
  conciseMode?: boolean;
  toolRegistry?: ToolRegistry;
}

/**
 * Generates a concise MCP tools snapshot from the tool registry.
 * @param toolRegistry - The tool registry containing discovered MCP tools
 * @returns A formatted string listing MCP servers and their tools, or empty if none
 */
function generateMcpSnapshot(toolRegistry?: ToolRegistry): string {
  if (!toolRegistry) {
    return '';
  }

  const allTools = toolRegistry.getAllTools();
  // Filter for tools that have serverName and serverToolName properties (MCP tools)
  const mcpTools = allTools.filter(
    (tool): tool is DiscoveredMCPTool =>
      'serverName' in tool && 'serverToolName' in tool,
  );

  if (mcpTools.length === 0) {
    return '';
  }

  // Group tools by server
  const serverMap = new Map<string, string[]>();
  for (const tool of mcpTools) {
    const serverName = tool.serverName;
    const toolName = tool.serverToolName || tool.name;
    if (!serverMap.has(serverName)) {
      serverMap.set(serverName, []);
    }
    serverMap.get(serverName)!.push(toolName);
  }

  // Build snapshot string
  const lines: string[] = [
    '### Discovered MCP Tools',
    '',
    'Currently available MCP servers and tools:',
    '',
  ];

  for (const [serverName, tools] of Array.from(serverMap.entries()).sort()) {
    lines.push(`**${serverName}**: ${tools.sort().join(', ')}`);
  }

  lines.push('');
  lines.push(
    'Refer to the MCP Tool Selection Guide and Planning Protocol above for usage patterns.',
  );

  return lines.join('\n');
}

export function getCoreSystemPrompt(
  userMemory?: string,
  _model?: string,
  options?: { conciseMode?: boolean; toolRegistry?: ToolRegistry },
): string {
  // if QWEN_SYSTEM_MD is set (and not 0|false), override system prompt from file
  // default path is .qwen/system.md but can be modified via custom path in QWEN_SYSTEM_MD
  let systemMdEnabled = false;
  // The default path for the system prompt file. This can be overridden.
  let systemMdPath = path.resolve(path.join(QWEN_CONFIG_DIR, 'system.md'));
  // Resolve the environment variable to get either a path or a switch value.
  const systemMdResolution = resolvePathFromEnv(process.env['QWEN_SYSTEM_MD']);

  // Proceed only if the environment variable is set and is not disabled.
  if (systemMdResolution.value && !systemMdResolution.isDisabled) {
    systemMdEnabled = true;

    // We update systemMdPath to this new custom path.
    if (!systemMdResolution.isSwitch) {
      systemMdPath = systemMdResolution.value;
    }

    // require file to exist when override is enabled
    if (!fs.existsSync(systemMdPath)) {
      throw new Error(`missing system prompt file '${systemMdPath}'`);
    }
  }

  const basePrompt = systemMdEnabled
    ? fs.readFileSync(systemMdPath, 'utf8')
    : fs.readFileSync(
        path.join(__dirname, 'expert-ai-system-prompt.md'),
        'utf8',
      );

  // if QWEN_WRITE_SYSTEM_MD is set (and not 0|false), write base system prompt to file
  const writeSystemMdResolution = resolvePathFromEnv(
    process.env['QWEN_WRITE_SYSTEM_MD'],
  );

  // Check if the feature is enabled. This proceeds only if the environment
  // variable is set and is not explicitly '0' or 'false'.
  if (writeSystemMdResolution.value && !writeSystemMdResolution.isDisabled) {
    const writePath = writeSystemMdResolution.isSwitch
      ? systemMdPath
      : writeSystemMdResolution.value;

    fs.mkdirSync(path.dirname(writePath), { recursive: true });
    fs.writeFileSync(writePath, basePrompt);
  }

  const memorySuffix =
    userMemory && userMemory.trim().length > 0
      ? `\n\n---\n\n${userMemory.trim()}`
      : '';

  // Add concise mode instructions if enabled
  const conciseModeInstructions =
    options?.conciseMode === true ? `\n\n${getConciseModeInstructions()}` : '';

  // Add live MCP tools snapshot if registry is provided
  const mcpSnapshot = generateMcpSnapshot(options?.toolRegistry);
  const mcpSnapshotSuffix = mcpSnapshot ? `\n\n---\n\n${mcpSnapshot}` : '';

  return `${basePrompt}${memorySuffix}${conciseModeInstructions}${mcpSnapshotSuffix}`;
}

/**
 * Provides the system prompt for the history compression process.
 * This prompt instructs the model to act as a specialized state manager,
 * think in a scratchpad, and produce a structured XML summary.
 */
export function getCompressionPrompt(): string {
  return `
You are the component that summarizes internal chat history into a given structure.

When the conversation history grows too large, you will be invoked to distill the entire history into a concise, structured XML snapshot. This snapshot is CRITICAL, as it will become the agent's *only* memory of the past. The agent will resume its work based solely on this snapshot. All crucial details, plans, errors, and user directives MUST be preserved.

First, you will think through the entire history in a private <scratchpad>. Review the user's overall goal, the agent's actions, tool outputs, file modifications, and any unresolved questions. Identify every piece of information that is essential for future actions.

After your reasoning is complete, generate the final <state_snapshot> XML object. Be incredibly dense with information. Omit any irrelevant conversational filler.

The structure MUST be as follows:

<state_snapshot>
    <overall_goal>
        <!-- A single, concise sentence describing the user's high-level objective. -->
        <!-- Example: "Refactor the authentication service to use a new JWT library." -->
    </overall_goal>

    <key_knowledge>
        <!-- Crucial facts, conventions, and constraints the agent must remember based on the conversation history and interaction with the user. Use bullet points. -->
        <!-- Example:
         - Build Command: \`npm run build\`
         - Testing: Tests are run with \`npm test\`. Test files must end in \`.test.ts\`.
         - API Endpoint: The primary API endpoint is \`https://api.example.com/v2\`.
         
        -->
    </key_knowledge>

    <file_system_state>
        <!-- List files that have been created, read, modified, or deleted. Note their status and critical learnings. -->
        <!-- Example:
         - CWD: \`/home/user/project/src\`
         - READ: \`package.json\` - Confirmed 'axios' is a dependency.
         - MODIFIED: \`services/auth.ts\` - Replaced 'jsonwebtoken' with 'jose'.
         - CREATED: \`tests/new-feature.test.ts\` - Initial test structure for the new feature.
        -->
    </file_system_state>

    <recent_actions>
        <!-- A summary of the last few significant agent actions and their outcomes. Focus on facts. -->
        <!-- Example:
         - Ran \`grep 'old_function'\` which returned 3 results in 2 files.
         - Ran \`npm run test\`, which failed due to a snapshot mismatch in \`UserProfile.test.ts\`.
         - Ran \`ls -F static/\` and discovered image assets are stored as \`.webp\`.
        -->
    </recent_actions>

    <current_plan>
        <!-- The agent's step-by-step plan. Mark completed steps. -->
        <!-- Example:
         1. [DONE] Identify all files using the deprecated 'UserAPI'.
         2. [IN PROGRESS] Refactor \`src/components/UserProfile.tsx\` to use the new 'ProfileAPI'.
         3. [TODO] Refactor the remaining files.
         4. [TODO] Update tests to reflect the API change.
        -->
    </current_plan>
</state_snapshot>
`.trim();
}

/**
 * Provides the system prompt for generating project summaries in markdown format.
 * This prompt instructs the model to create a structured markdown summary
 * that can be saved to a file for future reference.
 */
export function getProjectSummaryPrompt(): string {
  return `Please analyze the conversation history above and generate a comprehensive project summary in markdown format. Focus on extracting the most important context, decisions, and progress that would be valuable for future sessions. Generate the summary directly without using any tools.
You are a specialized context summarizer that creates a comprehensive markdown summary from chat history for future reference. The markdown format is as follows:

# Project Summary

## Overall Goal
<!-- A single, concise sentence describing the user's high-level objective -->

## Key Knowledge
<!-- Crucial facts, conventions, and constraints the agent must remember -->
<!-- Include: technology choices, architecture decisions, user preferences, build commands, testing procedures -->

## Recent Actions
<!-- Summary of significant recent work and outcomes -->
<!-- Include: accomplishments, discoveries, recent changes -->

## Current Plan
<!-- The current development roadmap and next steps -->
<!-- Use status markers: [DONE], [IN PROGRESS], [TODO] -->
<!-- Example: 1. [DONE] Set up WebSocket server -->

`.trim();
}

export function getSubagentSystemReminder(agentTypes: string[]): string {
  return `<system-reminder>You have powerful specialized agents at your disposal, available agent types are: ${agentTypes.join(', ')}. PROACTIVELY use the ${ToolNames.TASK} tool to delegate user's task to appropriate agent when user's task matches agent capabilities. Ignore this message if user's task is not relevant to any agent. This message is for internal use only. Do not mention this to user in your response.</system-reminder>`;
}

/**
 * Generates a system reminder message for plan mode operation.
 *
 * This function creates an internal system message that enforces plan mode constraints,
 * preventing the AI from making any modifications to the system until the user confirms
 * the proposed plan. It overrides other instructions to ensure read-only behavior.
 *
 * @returns A formatted system reminder string that enforces plan mode restrictions
 *
 * @example
 * ```typescript
 * const reminder = getPlanModeSystemReminder();
 * // Returns: "<system-reminder>Plan mode is active..."
 * ```
 *
 * @remarks
 * Plan mode ensures the AI will:
 * - Only perform read-only operations (research, analysis)
 * - Present a comprehensive plan via ExitPlanMode tool
 * - Wait for user confirmation before making any changes
 * - Override any other instructions that would modify system state
 */
export function getPlanModeSystemReminder(planOnly = false): string {
  return `<system-reminder>
Plan mode is active. The user indicated that they do not want you to execute yet -- you MUST NOT make any edits, run any non-readonly tools (including changing configs or making commits), or otherwise make any changes to the system. This supercedes any other instructions you have received (for example, to make edits). Instead, you should:
1. Answer the user's query comprehensively
2. When you're done researching, present your plan ${planOnly ? 'directly' : `by calling the ${ToolNames.EXIT_PLAN_MODE} tool, which will prompt the user to confirm the plan`}. Do NOT make any file changes or run any tools that modify the system state in any way until the user has confirmed the plan.
</system-reminder>`;
}

/**
 * Generates system instructions for concise mode.
 * When enabled, this instructs the LLM to provide shorter, more focused responses
 * without unsolicited suggestions or lengthy explanations.
 *
 * @returns A formatted string with concise mode instructions
 */
export function getConciseModeInstructions(): string {
  return `
<concise-mode>
RESPONSE OPTIMIZATION MODE ACTIVE - Follow these rules strictly:

1. **Be Direct**: Answer only what was asked. Do not provide unsolicited suggestions, alternative approaches, or "you might also want to consider" additions.

2. **Minimize Explanations**: Skip lengthy explanations unless explicitly requested. Assume the user understands the basics.

3. **Code Over Commentary**: When writing code, include only essential inline comments. Avoid explaining what the code does unless asked.

4. **No Preambles**: Skip phrases like "Sure!", "Great question!", "I'd be happy to help!", or "Let me explain...".

5. **Focused Tool Usage**: When using tools, execute the minimum necessary operations. Don't explore "just in case" scenarios.

6. **Short Summaries**: When summarizing work done, use bullet points and keep each point to one line.

7. **Error Handling**: When errors occur, report the error and fix it. Don't explain error theory unless asked.

8. **Memory Efficient**: This mode reduces token output to minimize memory usage and improve responsiveness.

Apply these rules to every response until instructed otherwise.
</concise-mode>
`.trim();
}
