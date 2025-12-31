# Bug Bounty Platform Integration

DarkCoder integrates with major bug bounty platforms to help security researchers and bug hunters find and explore programs.

## Supported Platforms

| Platform      | API Support | Notes                                         |
| ------------- | ----------- | --------------------------------------------- |
| **HackerOne** | ✅ Full     | Username + API Token required for full access |
| **Bugcrowd**  | ✅ Full     | Bearer token required for full access         |
| **Intigriti** | ✅ Full     | API token required for full access            |
| **YesWeHack** | ✅ Full     | API token required for full access            |
| **Immunefi**  | ✅ Public   | No API key needed (Web3/DeFi focus)           |
| **Synack**    | ⚠️ Limited  | Invite-only platform                          |

## Configuration

### Setting Up API Keys

Use the API Key Manager tool to configure your credentials:

```bash
# List available platforms
darkcoder> { "tool": "api_key_manager", "operation": "list" }

# Set HackerOne credentials
darkcoder> { "tool": "api_key_manager", "operation": "set", "tool": "hackerone", "apiId": "your_username", "apiSecret": "your_api_token" }

# Set Bugcrowd token
darkcoder> { "tool": "api_key_manager", "operation": "set", "tool": "bugcrowd", "apiKey": "your_bearer_token" }

# Set Intigriti token
darkcoder> { "tool": "api_key_manager", "operation": "set", "tool": "intigriti", "apiKey": "your_api_token" }
```

Or use environment variables:

```bash
# HackerOne
export HACKERONE_API_USERNAME="your_username"
export HACKERONE_API_TOKEN="your_api_token"

# Bugcrowd
export BUGCROWD_API_TOKEN="your_bearer_token"

# Intigriti
export INTIGRITI_API_TOKEN="your_api_token"

# YesWeHack
export YESWEHACK_API_TOKEN="your_api_token"

# Immunefi (optional - public API)
export IMMUNEFI_API_KEY="your_api_key"
```

## Usage

### Search Programs

Search across all platforms:

```json
{ "tool": "bug_bounty", "operation": "search", "query": "google" }
```

Search specific platform:

```json
{
  "tool": "bug_bounty",
  "operation": "search",
  "query": "crypto",
  "platform": "immunefi"
}
```

### Get Platform Statistics

```json
{ "tool": "bug_bounty", "operation": "stats" }
```

```json
{ "tool": "bug_bounty", "operation": "stats", "platform": "hackerone" }
```

### Find Trending Programs

```json
{ "tool": "bug_bounty", "operation": "trending" }
```

### Get Program Details

```json
{ "tool": "bug_bounty", "operation": "program", "program": "uber" }
```

### Get Program Scope

```json
{ "tool": "bug_bounty", "operation": "scope", "program": "github" }
```

### List Programs with Filters

```json
{
  "tool": "bug_bounty",
  "operation": "list",
  "platform": "hackerone",
  "limit": 20,
  "filter": {
    "minBounty": 1000,
    "managed": true
  }
}
```

## Example Workflows

### 1. Finding High-Paying Programs

```
User: Find bug bounty programs with bounties over $50,000

DarkCoder will:
1. Search across all platforms
2. Filter by bounty range
3. Present programs like Coinbase, Immunefi Web3 programs, etc.
```

### 2. Web3 Security Research

```
User: I want to hunt on DeFi programs

DarkCoder will:
1. Focus on Immunefi platform
2. Show programs like Wormhole, MakerDAO, Uniswap
3. Provide max bounty information (up to $10M+)
```

### 3. Starting Bug Bounty

```
User: I'm new to bug bounty, what programs should I start with?

DarkCoder will:
1. Suggest VDP (Vulnerability Disclosure Programs)
2. Recommend beginner-friendly programs
3. Provide tips and resources
```

## Platform-Specific Information

### HackerOne

- **API Docs:** https://api.hackerone.com/
- **Registration:** https://hackerone.com/users/sign_up
- **Known for:** Enterprise programs, largest platform

### Bugcrowd

- **API Docs:** https://docs.bugcrowd.com/api/getting-started/
- **Registration:** https://bugcrowd.com/user/sign_up
- **Known for:** Managed programs, researcher community

### Intigriti

- **API Docs:** https://kb.intigriti.com/en/articles/3759275-intigriti-api
- **Registration:** https://login.intigriti.com/account/register
- **Known for:** European programs, GDPR compliance

### YesWeHack

- **API Docs:** https://api.yeswehack.com/docs
- **Registration:** https://yeswehack.com/auth/register/hacker
- **Known for:** French/European programs

### Immunefi

- **Website:** https://immunefi.com/
- **Known for:** Highest bounties (up to $10M), Web3/DeFi focus
- **Public API:** No authentication required for basic searches

## Tips for Bug Bounty Hunters

1. **Read the Rules** - Every program has unique rules and scope
2. **Start with VDPs** - Vulnerability Disclosure Programs are great for practice
3. **Quality > Quantity** - Well-written reports get paid
4. **Use Automation Wisely** - Manual testing finds unique bugs
5. **Build Relationships** - Good reports lead to private invites
6. **Specialize** - Focus on specific vulnerability types or industries
7. **Stay Updated** - New programs launch frequently

## Resources

- [HackerOne Directory](https://hackerone.com/directory)
- [Bugcrowd Programs](https://bugcrowd.com/programs)
- [Immunefi Bounties](https://immunefi.com/explore/)
- [Chaos - Scope Lists](https://chaos.projectdiscovery.io/)
- [Bug Bounty Forum](https://bugbountyforum.com/)
