/**
 * @license
 * Copyright 2025 DarkCoder
 * SPDX-License-Identifier: Apache-2.0
 */

import type React from 'react';
import { useState, useMemo, useCallback } from 'react';
import { Box, Text } from 'ink';
import TextInput from 'ink-text-input';
import process from 'node:process';
import { theme } from '../semantic-colors.js';
import { useKeypress } from '../hooks/useKeypress.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

interface SecurityToolsDialogProps {
  onClose: () => void;
}

interface SecurityTool {
  id: string;
  name: string;
  description: string;
  category: string;
  envVars: string[];
  settingsPath: string;
  registrationUrl: string;
}

const SECURITY_TOOLS: SecurityTool[] = [
  {
    id: 'censys',
    name: 'Censys',
    description: 'Internet asset discovery and certificates',
    category: 'Internet Scanning',
    envVars: ['CENSYS_API_ID', 'CENSYS_API_SECRET'],
    settingsPath: 'advanced.censysApiId / censysApiSecret',
    registrationUrl: 'https://search.censys.io/register',
  },
  {
    id: 'urlscan',
    name: 'URLScan.io',
    description: 'Website scanning and threat analysis',
    category: 'Web Analysis',
    envVars: ['URLSCAN_API_KEY'],
    settingsPath: 'advanced.urlscanApiKey',
    registrationUrl: 'https://urlscan.io/user/signup',
  },
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'File and URL malware analysis',
    category: 'Threat Intelligence',
    envVars: ['VIRUSTOTAL_API_KEY'],
    settingsPath: 'advanced.virusTotalApiKey',
    registrationUrl: 'https://www.virustotal.com/gui/join-us',
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'IP threat intelligence platform',
    category: 'Threat Intelligence',
    envVars: ['GREYNOISE_API_KEY'],
    settingsPath: 'advanced.greynoiseApiKey',
    registrationUrl: 'https://viz.greynoise.io/signup',
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'IP address reputation checker',
    category: 'Threat Intelligence',
    envVars: ['ABUSEIPDB_API_KEY'],
    settingsPath: 'advanced.abuseipdbApiKey',
    registrationUrl: 'https://www.abuseipdb.com/register',
  },
  {
    id: 'securitytrails',
    name: 'SecurityTrails',
    description: 'DNS and subdomain intelligence',
    category: 'Domain/DNS',
    envVars: ['SECURITYTRAILS_API_KEY'],
    settingsPath: 'advanced.securitytrailsApiKey',
    registrationUrl: 'https://securitytrails.com/app/signup',
  },
  {
    id: 'hunter',
    name: 'Hunter.io',
    description: 'Email finder for OSINT',
    category: 'Domain/DNS',
    envVars: ['HUNTER_API_KEY'],
    settingsPath: 'advanced.hunterApiKey',
    registrationUrl: 'https://hunter.io/users/sign_up',
  },
];

/**
 * SecurityToolsDialog - Information and management for security tool API keys
 */
export function SecurityToolsDialog({
  onClose,
}: SecurityToolsDialogProps): React.JSX.Element {
  // Start at 1 to skip the first category header
  const [selectedIndex, setSelectedIndex] = useState(1);
  const [isEditingKey, setIsEditingKey] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [statusMessage, setStatusMessage] = useState<{
    text: string;
    type: 'success' | 'error';
  } | null>(null);

  // Check if tool has API key configured
  const hasApiKey = useCallback((tool: SecurityTool): boolean => tool.envVars.some((env) => !!process.env[env]), []);

  // Group tools by category
  const groupedTools = useMemo(() => {
    const groups: Record<string, SecurityTool[]> = {};
    SECURITY_TOOLS.forEach((tool) => {
      if (!groups[tool.category]) {
        groups[tool.category] = [];
      }
      groups[tool.category]!.push(tool);
    });
    return groups;
  }, []);

  // Flatten tools for navigation
  const flatTools = useMemo(() => {
    const result: Array<SecurityTool | { isCategory: true; name: string }> = [];
    Object.entries(groupedTools).forEach(([category, tools]) => {
      result.push({ isCategory: true, name: category });
      result.push(...tools);
    });
    return result;
  }, [groupedTools]);

  // Save API key to settings.json
  const saveApiKey = useCallback(
    (tool: SecurityTool, apiKey: string): boolean => {
      try {
        const settingsDir = path.join(os.homedir(), '.qwen');
        const settingsPath = path.join(settingsDir, 'settings.json');

        // Create directory if it doesn't exist
        if (!fs.existsSync(settingsDir)) {
          fs.mkdirSync(settingsDir, { recursive: true });
        }

        // Read existing settings or create new object
        let settings: Record<string, unknown> = {};
        if (fs.existsSync(settingsPath)) {
          const content = fs.readFileSync(settingsPath, 'utf-8');
          settings = JSON.parse(content);
        }

        // Create advanced section if it doesn't exist
        if (!settings['advanced'] || typeof settings['advanced'] !== 'object') {
          settings['advanced'] = {};
        }

        // Set the API key based on tool ID
        const keyMap: Record<string, string> = {
          censys: 'censysApiId', // For Censys, we'll store the ID/secret separately
          urlscan: 'urlscanApiKey',
          virustotal: 'virusTotalApiKey',
          greynoise: 'greynoiseApiKey',
          abuseipdb: 'abuseipdbApiKey',
          securitytrails: 'securitytrailsApiKey',
          hunter: 'hunterApiKey',
        };

        const settingsKey = keyMap[tool.id];
        if (settingsKey) {
          (settings['advanced'] as Record<string, unknown>)[settingsKey] =
            apiKey;
        } // Write back to file
        fs.writeFileSync(settingsPath, JSON.stringify(settings, null, 2));

        // Also set environment variable for current session
        if (tool.envVars[0]) {
          process.env[tool.envVars[0]] = apiKey;
        }

        return true;
      } catch (error) {
        console.error('Failed to save API key:', error);
        return false;
      }
    },
    [],
  );

  // Handle API key submission
  const handleSubmitApiKey = useCallback(() => {
    const selectedTool =
      selectedIndex < flatTools.length &&
      !('isCategory' in flatTools[selectedIndex]!)
        ? (flatTools[selectedIndex] as SecurityTool)
        : null;

    if (!selectedTool || !apiKeyInput.trim()) {
      setStatusMessage({ text: 'Invalid API key', type: 'error' });
      setIsEditingKey(false);
      setApiKeyInput('');
      return;
    }

    const success = saveApiKey(selectedTool, apiKeyInput.trim());
    if (success) {
      setStatusMessage({
        text: `✅ ${selectedTool.name} API key saved successfully!`,
        type: 'success',
      });
    } else {
      setStatusMessage({
        text: `❌ Failed to save ${selectedTool.name} API key`,
        type: 'error',
      });
    }

    setIsEditingKey(false);
    setApiKeyInput('');

    // Clear status message after 3 seconds
    setTimeout(() => setStatusMessage(null), 3000);
  }, [selectedIndex, flatTools, apiKeyInput, saveApiKey]);

  // Keyboard handlers
  useKeypress(
    (key) => {
      // Don't handle keys when editing
      if (isEditingKey) {
        return;
      }

      if (key.name === 'escape' || key.name === 'q') {
        onClose();
        return;
      }

      if (key.name === 'return' || key.name === 'enter') {
        // Start editing mode to paste API key
        setIsEditingKey(true);
        setApiKeyInput('');
        setStatusMessage(null);
        return;
      }

      if (key.name === 'up' || key.name === 'k') {
        setSelectedIndex((prev) => {
          let newIndex = prev - 1;
          while (newIndex >= 0 && 'isCategory' in flatTools[newIndex]!) {
            newIndex--;
          }
          return newIndex >= 0 ? newIndex : prev;
        });
      } else if (key.name === 'down' || key.name === 'j') {
        setSelectedIndex((prev) => {
          let newIndex = prev + 1;
          while (
            newIndex < flatTools.length &&
            'isCategory' in flatTools[newIndex]!
          ) {
            newIndex++;
          }
          return newIndex < flatTools.length ? newIndex : prev;
        });
      }
    },
    { isActive: !isEditingKey },
  );

  const configuredCount = SECURITY_TOOLS.filter(hasApiKey).length;
  const selectedTool =
    selectedIndex < flatTools.length &&
    !('isCategory' in flatTools[selectedIndex]!)
      ? (flatTools[selectedIndex] as SecurityTool)
      : null;

  return (
    <Box flexDirection="column" paddingX={2} paddingY={1}>
      <Box marginBottom={1}>
        <Text bold color={theme.text.secondary}>
          🔐 Security Tools API Keys
        </Text>
      </Box>

      <Box marginBottom={1}>
        <Text dimColor>
          Configured: {configuredCount}/{SECURITY_TOOLS.length} tools
        </Text>
      </Box>

      {/* Status message */}
      {statusMessage && (
        <Box marginBottom={1}>
          <Text color={statusMessage.type === 'success' ? 'green' : 'red'}>
            {statusMessage.text}
          </Text>
        </Box>
      )}

      <Box flexDirection="row" marginBottom={1}>
        {/* Left column - Tool list */}
        <Box flexDirection="column" width="50%">
          {flatTools.map((item, index) => {
            if ('isCategory' in item) {
              return (
                <Box key={`cat-${item.name}`} marginTop={1}>
                  <Text bold color={theme.text.secondary}>
                    ▸ {item.name}
                  </Text>
                </Box>
              );
            }

            const tool = item;
            const isSelected = index === selectedIndex;
            const configured = hasApiKey(tool);

            return (
              <Box key={tool.id} marginLeft={2}>
                <Text color={isSelected ? theme.text.secondary : undefined}>
                  {isSelected ? '❯ ' : '  '}
                  {configured ? '✅' : '⬜'} {tool.name}
                </Text>
              </Box>
            );
          })}
        </Box>

        {/* Right column - Selected tool details */}
        <Box
          flexDirection="column"
          width="50%"
          borderStyle="single"
          borderColor="gray"
          paddingX={1}
        >
          {selectedTool ? (
            <>
              <Text bold color={theme.text.secondary}>
                {selectedTool.name}
              </Text>
              <Box marginBottom={1}>
                <Text dimColor>{selectedTool.description}</Text>
              </Box>

              <Text bold>Status:</Text>
              <Box marginBottom={1}>
                <Text color={hasApiKey(selectedTool) ? 'green' : 'yellow'}>
                  {hasApiKey(selectedTool)
                    ? '✅ Configured'
                    : '⬜ Not configured'}
                </Text>
              </Box>

              <Text bold>Registration:</Text>
              <Box marginBottom={1}>
                <Text color={theme.text.secondary}>
                  {selectedTool.registrationUrl}
                </Text>
              </Box>

              <Text bold>Environment Variables:</Text>
              {selectedTool.envVars.map((env) => (
                <Text key={env} dimColor>
                  • {env}
                </Text>
              ))}

              <Box marginTop={1}>
                <Text bold>Settings Path:</Text>
              </Box>
              <Text dimColor>{selectedTool.settingsPath}</Text>

              {/* API Key Input Section */}
              {isEditingKey && (
                <Box
                  flexDirection="column"
                  marginTop={2}
                  borderStyle="single"
                  borderColor="cyan"
                  paddingX={1}
                  paddingY={1}
                >
                  <Text bold color="cyan">
                    📋 Paste API Key for {selectedTool.name}:
                  </Text>
                  <Box marginTop={1}>
                    <Text color={theme.text.secondary}>Key: </Text>
                    <TextInput
                      value={apiKeyInput}
                      onChange={setApiKeyInput}
                      onSubmit={handleSubmitApiKey}
                      placeholder="Paste your API key here..."
                      mask="*"
                    />
                  </Box>
                  <Box marginTop={1}>
                    <Text dimColor>
                      Press <Text bold>Enter</Text> to save,{' '}
                      <Text bold>Ctrl+C</Text> to cancel
                    </Text>
                  </Box>
                </Box>
              )}

              {!isEditingKey && (
                <Box marginTop={2} paddingX={1}>
                  <Text color="cyan" bold>
                    💡 Press <Text color="green">Enter ↵</Text> to add/update
                    API key
                  </Text>
                </Box>
              )}
            </>
          ) : (
            <Text dimColor>Select a tool to view details</Text>
          )}
        </Box>
      </Box>

      {!isEditingKey && (
        <>
          <Box
            flexDirection="column"
            borderStyle="single"
            borderColor="gray"
            paddingX={1}
            marginTop={1}
          >
            <Text bold color={theme.text.secondary}>
              Quick Setup:
            </Text>
            <Text dimColor>
              1.{' '}
              <Text bold color="green">
                ↑/↓ or j/k:
              </Text>{' '}
              Select a tool
            </Text>
            <Text dimColor>
              2.{' '}
              <Text bold color="green">
                Enter ↵:
              </Text>{' '}
              Paste your API key
            </Text>
            <Text dimColor>
              3.{' '}
              <Text bold color="green">
                Enter ↵:
              </Text>{' '}
              Save and activate
            </Text>
          </Box>

          <Box
            flexDirection="column"
            borderStyle="single"
            borderColor="gray"
            paddingX={1}
            marginTop={1}
          >
            <Text dimColor>
              <Text bold>↑/↓ or j/k:</Text> Navigate tools
            </Text>
            <Text dimColor>
              <Text bold>Enter ↵:</Text> Add/Update API key
            </Text>
            <Text dimColor>
              <Text bold>q or Esc:</Text> Close
            </Text>
          </Box>
        </>
      )}
    </Box>
  );
}
