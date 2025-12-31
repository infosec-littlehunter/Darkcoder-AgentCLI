# MCP Server Setup for WSL2 (Kali Linux)

This guide explains how to configure MCP servers for DarkCoder running on Kali Linux WSL2.

## Configuration File Location

MCP servers are configured in `~/.qwen/settings.json` under the `mcpServers` key.

## Your Current Configuration

Your settings file is located at: `~/.qwen/settings.json`

### Configured MCP Servers

| Server         | Type  | Description                 | Status                        |
| -------------- | ----- | --------------------------- | ----------------------------- |
| `docker`       | stdio | Docker container management | Requires Docker in WSL        |
| `burp`         | SSE   | Burp Suite MCP proxy        | Requires Windows Burp running |
| `drawdb`       | HTTP  | Database diagramming        | Requires Windows service      |
| `filesystem`   | stdio | File system access          | Ready to use                  |
| `github`       | stdio | GitHub API access           | Needs GITHUB_TOKEN            |
| `fetch`        | stdio | Web fetching                | Ready to use                  |
| `brave-search` | stdio | Brave search API            | Needs BRAVE_API_KEY           |

## WSL2 to Windows Communication

Your Windows host IP is: `10.255.255.254` (from `/etc/resolv.conf`)

For MCP servers running on Windows, use this IP to connect from WSL2.

## Setting Up Each Server

### 1. Docker MCP (Ready ✅)

Docker MCP is pre-configured and the image is pulled. Just ensure Docker is running:

```bash
# Verify Docker is working
docker ps

# Test Docker MCP
docker run -i --rm -v /var/run/docker.sock:/var/run/docker.sock mcp/docker
```

### 2. Burp Suite MCP (Requires Windows Setup)

On your **Windows** machine:

1. Start Burp Suite
2. Enable the MCP proxy extension
3. Ensure it's listening on port `9876`
4. Allow connections from WSL2 IP range

**Firewall Rule (PowerShell as Admin):**

```powershell
New-NetFirewallRule -DisplayName "Burp MCP" -Direction Inbound -LocalPort 9876 -Protocol TCP -Action Allow
```

### 3. DrawDB MCP (Requires Windows Setup)

On your **Windows** machine:

1. Start the drawdb-mcp server
2. Ensure it's listening on port `3000`
3. Allow connections from WSL2

### 4. Filesystem MCP (Ready ✅)

Already configured to access `/home/littlekid`. The server starts automatically when you use DarkCoder.

### 5. GitHub MCP (Needs Token)

Set your GitHub Personal Access Token:

```bash
# Add to ~/.bashrc or ~/.zshrc
export GITHUB_TOKEN="ghp_your_token_here"

# Or use the CLI
qwen mcp add github npx -y @modelcontextprotocol/server-github \
  -e GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_token
```

### 6. Fetch MCP (Ready ✅)

Web fetching server - works out of the box.

### 7. Brave Search MCP (Needs API Key)

Get a free API key from: https://brave.com/search/api/

```bash
export BRAVE_API_KEY="your_brave_api_key"
```

## Using MCP Servers

### List Configured Servers

```bash
qwen mcp list
```

### Add a New Server

```bash
# Stdio server
qwen mcp add my-server python /path/to/server.py

# HTTP server
qwen mcp add --transport http my-http-server http://localhost:8080

# SSE server
qwen mcp add --transport sse my-sse-server http://localhost:9090/sse
```

### Remove a Server

```bash
qwen mcp remove server-name
```

## Using MCP Tools in Chat

Once connected, MCP tools appear in your DarkCoder session. Use them like:

```
> Use the docker tool to list all running containers

> Use the fetch tool to get content from https://example.com

> Use the filesystem tool to read /home/littlekid/myfile.txt
```

## Troubleshooting

### Server Shows "Disconnected"

This is normal! Servers connect when you start a chat session, not when listing.

### Can't Connect to Windows Services

1. Check Windows firewall allows the port
2. Verify the service is running on Windows
3. Test connectivity: `curl http://10.255.255.254:PORT`
4. WSL2 IP might change - check `/etc/resolv.conf`

### Docker Permission Denied

```bash
sudo usermod -aG docker $USER
# Then log out and back in
```

### npx Servers Not Starting

Clear npm cache and retry:

```bash
npx clear-npx-cache
```

## Security Considerations

- Set `"trust": false` for untrusted servers (requires confirmation for tool calls)
- Set `"trust": true` only for servers you fully trust (bypasses confirmations)
- Use `includeTools` to whitelist specific tools
- Use `excludeTools` to blacklist dangerous tools

Example with filtering:

```json
{
  "mcpServers": {
    "safe-server": {
      "command": "python",
      "args": ["server.py"],
      "includeTools": ["read_file", "list_dir"],
      "excludeTools": ["delete_file", "execute_command"],
      "trust": false
    }
  }
}
```
