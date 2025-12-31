#!/usr/bin/env node

/**
 * Verification script to check which security tools are registered
 * and available in the tool registry
 */

import { Config } from '../packages/core/src/config/config.js';

async function verifySecurityTools() {
  console.log('🔍 Verifying Security Tools Registration...\n');

  try {
    // Create a minimal config instance
    const config = new Config();

    // Create the tool registry
    const registry = await config.createToolRegistry();

    // Get all tools
    const allTools = registry.getAllTools();
    const allToolNames = registry.getAllToolNames();

    console.log(`📊 Total tools registered: ${allTools.length}\n`);

    // Security tools we expect to find
    const expectedSecurityTools = [
      'shodan',
      'virustotal',
      'censys',
      'urlscan',
      'yaraify',
      'cuckoo_sandbox',
      'wayback_machine',
      'web_tech',
      'security_intel',
      'cis_benchmark',
      'bug_bounty',
      'api_key_manager',
    ];

    console.log('🔐 Checking for Security Tools:\n');

    const foundTools = [];
    const missingTools = [];

    for (const toolName of expectedSecurityTools) {
      const found = allToolNames.some((name) =>
        name.toLowerCase().includes(toolName.toLowerCase()),
      );

      if (found) {
        const actualName = allToolNames.find((name) =>
          name.toLowerCase().includes(toolName.toLowerCase()),
        );
        foundTools.push(actualName);
        console.log(`  ✅ ${actualName}`);
      } else {
        missingTools.push(toolName);
        console.log(`  ❌ ${toolName} - NOT FOUND`);
      }
    }

    console.log(`\n📈 Results:`);
    console.log(
      `  Found: ${foundTools.length}/${expectedSecurityTools.length}`,
    );
    console.log(
      `  Missing: ${missingTools.length}/${expectedSecurityTools.length}`,
    );

    if (missingTools.length > 0) {
      console.log(`\n⚠️  Missing tools: ${missingTools.join(', ')}`);
    }

    // Check for MCP tools vs native tools
    console.log('\n🔍 Tool Type Analysis:');
    const mcpTools = allTools.filter((tool) => 'serverName' in tool);
    const nativeTools = allTools.filter((tool) => !('serverName' in tool));

    console.log(`  Native tools: ${nativeTools.length}`);
    console.log(`  MCP tools: ${mcpTools.length}`);

    console.log('\n📝 All Native Tool Names:');
    nativeTools.forEach((tool) => {
      console.log(`  - ${tool.name} (${tool.displayName})`);
    });
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

verifySecurityTools();
