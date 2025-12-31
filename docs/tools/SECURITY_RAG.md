# Security RAG Pipeline

The Security RAG (Retrieval-Augmented Generation) Pipeline provides intelligent access to security hardening documentation, CIS Benchmarks, Microsoft Security guides, and compliance frameworks.

## Features

- **CIS Benchmarks**: Ubuntu, Windows Server, RHEL, AWS, Azure, GCP, Kubernetes, Docker
- **Microsoft Security**: Defender for Endpoint, Intune, Azure Security Center, Sentinel
- **Compliance Frameworks**: NIST CSF, CIS Controls v8, PCI DSS, HIPAA, SOC2, ISO 27001
- **Semantic Search**: Natural language queries to find relevant security guidance
- **Hardening Recommendations**: Platform-specific security configuration guidance
- **Compliance Mapping**: Cross-reference controls across frameworks
- **URL-based Ingestion**: Fetch security documentation from URLs
- **Microsoft Learn Integration**: Automatically fetch Microsoft Learn documentation

## Usage

### Using the CLI Tool

The `cis_benchmark` tool is automatically available in DarkCoder. Here are some example queries:

#### Search Security Documentation

```
Search for SSH hardening best practices:
{ "mode": "search", "query": "SSH hardening disable root login" }
```

#### Get Hardening Recommendations

```
Get Ubuntu 22.04 hardening recommendations (Level 1):
{ "mode": "hardening", "platform": "ubuntu_22.04", "profileLevel": "L1" }

Get Windows Server 2022 hardening recommendations:
{ "mode": "hardening", "platform": "windows_server_2022" }

Get Kubernetes cluster hardening:
{ "mode": "hardening", "platform": "kubernetes" }

Get AWS security best practices:
{ "mode": "hardening", "platform": "aws" }

Get Azure security configuration:
{ "mode": "hardening", "platform": "azure" }

Get Docker container security:
{ "mode": "hardening", "platform": "docker" }
```

#### Get Compliance Guidance

```
Get NIST CSF compliance guidance:
{ "mode": "compliance", "framework": "NIST CSF", "query": "access control" }

Get PCI DSS encryption requirements:
{ "mode": "compliance", "framework": "PCI DSS", "query": "encryption" }
```

#### Get Microsoft Security Recommendations

```
Get Defender for Endpoint configuration:
{ "mode": "microsoft", "category": "defender_endpoint" }

Get Intune security policies:
{ "mode": "microsoft", "category": "intune", "query": "device compliance" }
```

#### Fetch from URLs

```
Fetch security documentation from a URL:
{ "mode": "fetch", "url": "https://example.com/security-guide.html" }

Fetch Microsoft Learn docs for a category:
{ "mode": "fetch", "category": "defender_endpoint" }

Fetch Intune documentation:
{ "mode": "fetch", "category": "intune" }
```

#### List Available Platforms

```
{ "mode": "list_platforms" }
```

#### View Knowledge Base Statistics

```
{ "mode": "stats" }
```

### Supported Platforms

#### CIS Benchmarks

| Platform            | Key                   |
| ------------------- | --------------------- |
| Ubuntu 22.04 LTS    | `ubuntu_22.04`        |
| Ubuntu 20.04 LTS    | `ubuntu_20.04`        |
| Windows Server 2022 | `windows_server_2022` |
| Windows Server 2019 | `windows_server_2019` |
| Windows 11          | `windows_11`          |
| Windows 10          | `windows_10`          |
| RHEL 9              | `rhel_9`              |
| RHEL 8              | `rhel_8`              |
| CentOS Stream 9     | `centos_stream_9`     |
| Debian 12           | `debian_12`           |
| Debian 11           | `debian_11`           |
| AWS                 | `aws`                 |
| Azure               | `azure`               |
| GCP                 | `gcp`                 |
| Kubernetes          | `kubernetes`          |
| Docker              | `docker`              |

#### Microsoft Security Categories

| Category              | Key                     |
| --------------------- | ----------------------- |
| Defender for Endpoint | `defender_endpoint`     |
| Defender for Cloud    | `defender_cloud`        |
| Defender for Identity | `defender_identity`     |
| Azure Security Center | `azure_security_center` |
| Intune                | `intune`                |
| Entra ID              | `entra_id`              |
| Sentinel              | `sentinel`              |
| Purview               | `purview`               |
| Security Baselines    | `security_baselines`    |
| Windows Security      | `windows_security`      |
| Office 365 Security   | `office_365_security`   |

### Profile Levels

CIS Benchmarks define two profile levels:

- **L1 (Level 1)**: Essential security settings that provide clear security benefit with minimal impact on functionality
- **L2 (Level 2)**: Defense-in-depth security settings for high-security environments

## Ingesting Custom Documentation

You can extend the knowledge base with your own security documentation:

```
Ingest a JSON file with CIS controls:
{
  "mode": "ingest",
  "source": "cis_benchmark",
  "platform": "ubuntu_22.04",
  "filePath": "/path/to/cis-controls.json"
}

Ingest Microsoft security documentation:
{
  "mode": "ingest",
  "source": "microsoft_security",
  "category": "defender_endpoint",
  "filePath": "/path/to/defender-config.json"
}
```

### Document Formats

The pipeline supports:

- **JSON**: Structured benchmark/recommendation data
- **Markdown**: Documentation with headers for section splitting
- **Plain Text**: General documentation

### JSON Format for CIS Benchmarks

```json
{
  "platform": "ubuntu_22.04",
  "version": "1.0.0",
  "controls": [
    {
      "id": "1.1.1",
      "title": "Ensure cramfs is disabled",
      "description": "The cramfs filesystem...",
      "rationale": "Removing support for...",
      "audit": "Run: modprobe -n -v cramfs",
      "remediation": "Edit /etc/modprobe.d/cramfs.conf...",
      "profileLevel": "L1",
      "section": "Filesystem Configuration",
      "cisControlsV8": ["4.1"],
      "nistCsf": ["PR.IP-1"]
    }
  ]
}
```

### JSON Format for Microsoft Security

```json
{
  "category": "defender_endpoint",
  "recommendations": [
    {
      "id": "mde-001",
      "title": "Enable Real-time Protection",
      "description": "Real-time protection monitors...",
      "severity": "high",
      "implementationGuide": "Enable via Group Policy...",
      "commands": ["Set-MpPreference -DisableRealtimeMonitoring $false"],
      "policyReference": "Computer Configuration > ..."
    }
  ]
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   CIS Benchmark Tool                         │
│                  (CLI Integration)                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│               Security RAG Pipeline                          │
│  • Search orchestration                                      │
│  • Built-in benchmark data                                   │
│  • Response formatting                                       │
└─────────────────────────────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│   Document    │  │   Embedding   │  │    Vector     │
│   Processor   │  │   Service     │  │    Store      │
│  • Parse docs │  │  • OpenAI     │  │  • Indexing   │
│  • Chunking   │  │  • DashScope  │  │  • Search     │
│  • Metadata   │  │  • Local      │  │  • Persist    │
└───────────────┘  └───────────────┘  └───────────────┘
```

## Configuration

The RAG pipeline can be configured via environment variables:

| Variable            | Description                      | Default |
| ------------------- | -------------------------------- | ------- |
| `OPENAI_API_KEY`    | OpenAI API key for embeddings    | -       |
| `DASHSCOPE_API_KEY` | DashScope API key for embeddings | -       |

If no API key is configured, the pipeline uses local embeddings (TF-IDF based).

### Data Directory

By default, the index is stored in `~/.darkcoder/security-rag/`. This can be customized in the configuration.

## Example Use Cases

### System Hardening

> "How do I harden SSH on Ubuntu 22.04?"

The tool will search CIS Benchmarks and return relevant controls like:

- Disable root SSH login
- Use SSH key authentication
- Configure SSH protocol version
- Set appropriate permissions on SSH config

### Compliance Audit Preparation

> "What controls do I need for PCI DSS encryption requirements?"

Returns mapped controls from CIS Benchmarks and Microsoft Security docs that satisfy PCI DSS encryption requirements.

### SOC Team Response

> "What are the Defender for Endpoint ASR rules I should enable?"

Returns Microsoft security recommendations for Attack Surface Reduction rules with PowerShell commands.

### Red Team Planning

> "What are common Windows password policy weaknesses?"

Returns CIS Benchmark controls related to password policies and their rationale for security testing.
