# Changelog

All notable changes to DarkCoder will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2025-01-XX

### 🚀 Major Features

#### Live CVE Intelligence System

- **NEW**: Real-time vulnerability intelligence integration across 6+ security tools
- **NEW**: Automatic CVE cross-referencing with live databases:
  - NVD (National Vulnerability Database)
  - Exploit-DB (20,000+ exploits)
  - VirusTotal threat intelligence
  - Shodan vulnerability data
  - CISA KEV (Known Exploited Vulnerabilities) catalog
  - YARAify malware signatures

#### Enhanced Security Tools with CVE Intelligence

##### Nuclei Scanner

- Extracts CVE IDs from 10,000+ vulnerability templates
- Automatically generates live CVE intelligence for discovered vulnerabilities
- Memory-safe processing: max 30 products, 50 results scanned
- Set-based deduplication for optimal performance

##### Shodan Integration

- Maps exposed services → software products → known CVEs
- Automatic version detection and vulnerability correlation
- Memory limit: 20 products per scan
- O(1) set-based deduplication

##### Censys Integration

- Analyzes certificates and services → extracts software versions
- Correlates software with live CVE databases
- Memory limit: 20 products per scan
- Compound key deduplication (product:version)

##### Web Technology Detection

- Version-aware CVE recommendations for web stacks
- Filters critical categories: web-server, framework, cms, programming-language
- Memory limit: 15 products per scan
- Smart product key tracking

##### SSL/TLS Scanner

- Maps TLS/SSL vulnerabilities → related CVE exploits
- Coverage: POODLE, BEAST, DROWN, Heartbleed, and more
- Memory limit: 20 vulnerabilities per scan
- Automatic exploit availability checking

##### Reverse Engineering Tool

- **6 new live intelligence operations**:
  - `check_cves`: Query live CVE databases
  - `check_exploits`: Search Exploit-DB for PoCs
  - `threat_intel`: VirusTotal + Shodan intelligence
  - `check_yara_rules`: YARAify malware detection
  - `vendor_advisories`: Vendor security bulletins
  - `recent_attacks`: CISA KEV catalog
- Emphasis on manual analysis with automated intelligence support
- Memory-safe processing with absolute limits

### 🔒 Security & Performance Improvements

#### Multi-Layer Memory Defense System

- **Layer 1**: Per-tool input limits (15-50 products based on complexity)
- **Layer 2**: CVE helper output constraints (100KB max)
- **Layer 3**: Absolute safety limits (50 products max across all operations)
- **Layer 4**: Input validation with `safelyLimitProducts()`
- **Layer 5**: Output truncation as final safeguard

#### Algorithm Optimizations

- Replaced O(n²) `.find()` with O(1) Set lookups across all tools
- Early break conditions in all processing loops
- Bounded iteration with `.slice()` before processing
- Set-based deduplication: `seenCVEs`, `seenProducts`, `seenItems`
- Memory markers (`🔒 MEMORY OPTIMIZATION`) on all critical sections

#### Fixed Issues

- **CRITICAL**: JavaScript heap out of memory errors (FATAL ERROR: Ineffective mark-compacts)
- **FIXED**: Unbounded array growth in nuclei scanner (thousands of results)
- **FIXED**: O(n²) deduplication causing performance degradation
- **FIXED**: Missing limits on CVE intelligence output strings
- **FIXED**: Removed erroneous `CoreToolScheduler.dispose()` calls
- **CRITICAL FIX**: Runtime history memory leak causing heap overflow during long sessions
  - **Problem**: Chat history array grew unbounded → 4GB+ heap → crash
  - **Solution**: Sliding window history management
  - **Limits**: Max 1000 items, auto-trims to 800 when exceeded
  - **Result**: ~100-200 MB max memory (down from 4GB+)

#### Runtime Memory Optimization (New!)

- **Sliding Window History**: Automatically trims old chat history during long sessions
  - Maximum 1000 history items in memory
  - Auto-trims to 800 items when limit exceeded
  - Keeps most recent conversation context
  - Transparent to users
- **Prevents**: JavaScript heap overflow during extended CLI usage
- **Impact**: Can now run DarkCoder for hours without memory crashes

### 📝 Documentation Updates

- Added CVE Intelligence System documentation to README.md
- Updated memory safety guarantees and 5-layer defense system
- Enhanced tool descriptions with CVE integration features
- Added contribution guidelines for memory-safe security tools
- Created CHANGELOG.md for version tracking
- Updated Dockerfile with memory optimization flags

### 🛠️ Developer Experience

- All builds pass successfully with TypeScript strict mode
- Production-ready: tested with `--max-old-space-size=8192`
- Memory markers for easy code review
- Comprehensive testing requirements in CONTRIBUTING.md
- Security tool integration patterns documented

### 🎯 Use Cases

The CVE intelligence system addresses the AI training data cutoff problem:

**Before**: AI models only know vulnerabilities from their training data (e.g., up to April 2024)
**After**: Real-time correlation with current vulnerability landscape

**Example Workflow**:

1. Scan target with Nuclei → Extracts CVE-2024-1234
2. AI compares: What I know (training data) vs What's current (live databases)
3. Generates targeted security commands with latest exploit information
4. Provides vendor advisories and patch status

### ⚙️ Configuration Changes

- No breaking configuration changes
- CVE intelligence works automatically with existing API keys
- Optional: Set `YARAIFY_API_KEY` for enhanced malware detection
- Memory limits configurable via `NODE_OPTIONS` environment variable

---

## [0.6.0] - 2025-01-XX

### Features

- Multi-provider AI support (29+ models)
- Real-time cost tracking
- Malware analysis tools (VirusTotal, YARAify, Hybrid Analysis)
- Bug bounty platform integrations
- OSINT and reconnaissance tools
- AI/LLM security features

### Infrastructure

- Monorepo architecture with npm workspaces
- Docker support
- VS Code extension
- TypeScript SDK

---

## Migration Guide

### Upgrading from 0.6.0 to 0.7.0

**No Breaking Changes** - All existing functionality preserved.

**New Features Available**:

1. CVE intelligence automatically enhances existing security tool outputs
2. Memory optimizations prevent heap overflow on large scans
3. New reverse engineering intelligence operations

**Recommended Actions**:

1. Update to latest version: `npm install -g @darkcoder/darkcoder@latest`
2. No configuration changes required
3. Optional: Add `YARAIFY_API_KEY` for enhanced malware detection
4. Review new CVE intelligence capabilities in README.md

**Performance Improvements**:

- Expect faster scan processing with Set-based deduplication
- Reduced memory usage on large vulnerability scans
- No more heap overflow errors on intensive operations

---

## Support

For issues, questions, or contributions:

- GitHub: https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI
- Documentation: [docs/](docs/)
- Report bugs: [GitHub Issues](https://github.com/infosec-littlehunter/AssistanceAntiCyber-Darkcoder-CLI/issues)
