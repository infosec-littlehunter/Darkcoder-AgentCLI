### MCP-Based Tool Orchestration

```python
class MCPSecurityOrchestrator:
    def __init__(self):
        self.mcp_servers = {
            'kali': KaliMCPClient(),
            'browser': BrowserMCPClient(),
            'burp': BurpMCPClient()
        }

    def verify_connectivity(self):
        """Check all MCP servers before operations"""
        status = {}
        for name, client in self.mcp_servers.items():
            try:
                status[name] = client.ping()
            except Exception as e:
                status[name] = f"Unavailable: {e}"
        return status

    def execute_scenario_based_attack(self, target_url, scenario):
        """
        Execute attack based on scenario using intelligent tool selection.

        Args:
            target_url: Target URL to attack
            scenario: One of 'reconnaissance', 'vuln_scanning', 'auth_testing',
                     'xss_testing', 'sqli_testing', 'api_testing', 'directory_bruteforce'
        """
        results = {}

        # Scenario-based tool selection (implements the decision matrix)
        if scenario == 'reconnaissance':
            # Kali MCP primary, Browser MCP secondary
            results['subdomains'] = self.mcp_servers['kali'].call('subfinder_scan', {'domain': target_url})
            results['amass'] = self.mcp_servers['kali'].call('amass_scan', {'domain': target_url})
            # Browser verification
            self.mcp_servers['browser'].call('browser_navigate', {'url': f'https://{target_url}'})
            results['screenshot'] = self.mcp_servers['browser'].call('browser_screenshot', {})

        elif scenario == 'vuln_scanning':
            # Kali MCP primary, Burp MCP secondary
            results['nuclei'] = self.mcp_servers['kali'].call('nuclei_scan', {'target': target_url})
            results['nikto'] = self.mcp_servers['kali'].call('nikto_scan', {'target': target_url})
            # Burp verification
            results['proxy_history'] = self.mcp_servers['burp'].call('get_proxy_http_history', {'count': 50, 'offset': 0})

        elif scenario == 'auth_testing':
            # Browser MCP primary, Burp MCP secondary
            self.mcp_servers['browser'].call('browser_navigate', {'url': f'https://{target_url}/login'})
            # Intercept with Burp
            self.mcp_servers['burp'].call('set_proxy_intercept_state', {'intercepting': True})
            # Fill login form
            self.mcp_servers['browser'].call('browser_type', {
                'element': 'Username input',
                'ref': 'input[type="text"], input[type="email"]',
                'text': 'test@example.com',
                'submit': False
            })
            self.mcp_servers['browser'].call('browser_type', {
                'element': 'Password input',
                'ref': 'input[type="password"]',
                'text': 'password123',
                'submit': True
            })
            results['auth_requests'] = self.mcp_servers['burp'].call('get_proxy_http_history', {'count': 10, 'offset': 0})

        elif scenario == 'xss_testing':
            # Browser MCP primary, Kali MCP (dalfox) secondary
            self.mcp_servers['browser'].call('browser_navigate', {'url': target_url})
            # Inject XSS payload via JavaScript
            self.mcp_servers['browser'].call('chrome_inject_script', {
                'type': 'ISOLATED',
                'jsScript': '''
                    // Test for XSS sinks
                    document.querySelectorAll('input, textarea').forEach(el => {
                        el.value = '<img src=x onerror=alert(document.domain)>';
                    });
                '''
            })
            # Automated scanning with Dalfox
            results['dalfox'] = self.mcp_servers['kali'].call('dalfox_scan', {'url': target_url})

        elif scenario == 'sqli_testing':
            # Kali MCP primary, Burp MCP secondary
            results['sqlmap'] = self.mcp_servers['kali'].call('sqlmap_scan', {'url': f'{target_url}/search?q=test'})
            results['ghauri'] = self.mcp_servers['kali'].call('ghauri_scan', {'url': f'{target_url}/search?q=test'})
            # Manual testing with Burp
            results['repeater_tab'] = self.mcp_servers['burp'].call('create_repeater_tab', {
                'content': f'GET /search?q=test\' OR 1=1-- HTTP/1.1\\r\\nHost: {target_url}\\r\\n\\r\\n',
                'targetHostname': target_url,
                'targetPort': 443,
                'usesHttps': True
            })

        elif scenario == 'api_testing':
            # Burp MCP primary, Browser MCP secondary
            results['api_requests'] = self.mcp_servers['burp'].call('send_http1_request', {
                'content': f'GET /api/v1/users HTTP/1.1\\r\\nHost: {target_url}\\r\\n\\r\\n',
                'targetHostname': target_url,
                'targetPort': 443,
                'usesHttps': True
            })
            # Browser context for token extraction
            self.mcp_servers['browser'].call('browser_navigate', {'url': f'https://{target_url}'})
            results['local_storage'] = self.mcp_servers['browser'].call('chrome_inject_script', {
                'type': 'ISOLATED',
                'jsScript': 'return localStorage.getItem("token") || sessionStorage.getItem("token");'
            })

        elif scenario == 'directory_bruteforce':
            # Kali MCP primary, Browser MCP secondary
            results['gobuster'] = self.mcp_servers['kali'].call('gobuster_scan', {'url': target_url})
            results['ffuf'] = self.mcp_servers['kali'].call('ffuf_scan', {'url': target_url})
            # Visual verification of found directories
            if results.get('gobuster') and 'found_directories' in results['gobuster']:
                for directory in results['gobuster']['found_directories'][:5]:  # Check first 5
                    self.mcp_servers['browser'].call('browser_navigate', {'url': f'{target_url}/{directory}'})
                    results[f'screenshot_{directory}'] = self.mcp_servers['browser'].call('browser_screenshot', {})

        return results

class KaliMCPClient:
    def call(self, tool, params):
        """Execute Kali tool via MCP"""
        # Direct mapping to actual Kali MCP tool names
        tool_mapping = {
            # Reconnaissance
            'subfinder_scan': 'subfinder_scan',
            'amass_scan': 'amass_scan',
            'assetfinder_scan': 'assetfinder_scan',
            'httpx_scan': 'httpx_scan',
```
