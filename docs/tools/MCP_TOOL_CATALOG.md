# MCP Tool Capability Catalog

This catalog lists common MCP servers available in DarkCoder (including Docker MCP bundles) and the tools they expose, plus quick guidance on when to use each.

Note: Tool names may appear prefixed at runtime as `serverName__toolName` when name collisions occur. Use the unprefixed names below conceptually; the registry will expose the precise callable name.

## Shodan (Network Intelligence)

- get_host_info: Get detailed information about a specific IP address. Use for point lookups and confirming exposed services.
- get_ssl_info: Get SSL certificate information for a domain. Use for TLS investigations, issuer, expiry and SANs.
- scan_network_range: Scan a network range (CIDR) for devices. Use for broad asset discovery within a scope.
- search_iot_devices: Search for specific types of IoT devices. Use for targeted device-class hunts.
- search_shodan: Search Shodan's database for devices and services. Use for arbitrary queries, facets and complex filters.

## Obsidian (Vault Operations)

- obsidian_append_content: Append content to a new or existing file in the vault.
- obsidian_batch_get_file_contents: Return concatenated content of multiple files with headers.
- obsidian_complex_search: JsonLogic-based complex search (supports glob and regexp). Use for tag/field/logic searches.
- obsidian_delete_file: Delete a file or directory.
- obsidian_get_file_contents: Return the content of a single file.
- obsidian_get_periodic_note: Get current periodic note for a period.
- obsidian_get_recent_changes: Get recently modified files.
- obsidian_get_recent_periodic_notes: Recent periodic notes by type.
- obsidian_list_files_in_dir: List files/dirs in a specific directory.
- obsidian_list_files_in_vault: List files/dirs at vault root.
- obsidian_patch_content: Insert relative to a heading/block/frontmatter.
- obsidian_simple_search: Simple text search across all files. Use for quick full-text queries.

## NIST/NVD Vulnerability Intelligence

- get_temporal_context: Get current date and temporal context. Use FIRST for time-relative queries ("this year", "last 90 days", etc.).
- search_cves: Search CVEs by keyword with flexible time filtering. Split windows >120 days automatically. Use ISO 8601 dates.
- get_cve_by_id: Retrieve a CVE by CVE-ID.
- cves_by_cpe: List CVEs associated with a specific CPE.
- cve_change_history: Retrieve change history for a CVE or time window. Windows >120 days are split automatically.
- kevs_between: List CVEs added to CISA KEV in a date window (auto-splits >90 days).

Guidance:

- For relative time phrases, call get_temporal_context first, then compute concrete start/end dates for follow-up queries.
- For long ranges, prefer multiple chunked calls and aggregate.

## Hacker News Intelligence

- get_stories: Fetch stories by type: top, new, ask_hn, show_hn (no comments).
- get_story_info: Detailed story info including comments.
- get_user_info: User info, including submitted stories.
- search_stories: Story search; keep queries short (<5 words) for best recall.

## NPM Sentinel (Ecosystem & Supply Chain)

- npmSearch, npmLatest, npmVersions: Discover packages and versions.
- npmDeps, npmSize, npmTypes: Dependencies graph, bundle size, TypeScript availability.
- npmMaintainers, npmMaintenance, npmQuality, npmScore, npmRepoStats: Health/quality/maintainer and repo metrics.
- npmTrends: Download trends over time.
- npmDeprecated: Deprecation status.
- npmLicenseCompatibility: License compatibility checks.
- npmVulnerabilities: OSV.dev vulnerability check.
- npmPackageReadme, npmChangelogAnalysis, npmAlternatives, npmCompare: Docs, changelogs, comparisons, alternatives.

Guidance:

- For security risk: start with npmVulnerabilities → npmDeps (blast radius) → npmMaintenance/npmQuality.
- For adoption guidance: npmTrends → npmAlternatives/npmCompare → npmTypes.

## Python Refactoring Assistant

- analyze_python_file: File-level refactoring opportunities with guidance.
- analyze_python_package: Package/folder-wide refactoring analysis.
- analyze_security_and_patterns: Security scanning and modern patterns.
- analyze_test_coverage: Test coverage analysis and improvements.
- find_long_functions: Extraction candidates.
- find_package_issues: Structural/package-level issues.
- get_extraction_guidance: Step-by-step extraction guidance.
- get_package_metrics: Aggregated metrics.
- tdd_refactoring_guidance: Test-first refactor workflow.

Guidance:

- For safe changes, follow tdd*refactoring_guidance before code edits. Use analyze*\* tools to identify hot spots, then get_extraction_guidance to plan changes.

## Browser MCP (Headful Web Automation)

- Navigate, click, type, hover, go back/forward, window sizing, file upload.
- Evaluate JavaScript on page/elements; capture screenshots and accessibility snapshots.
- Retrieve browser console logs.

Guidance:

- Use for sites needing interactive flows, auth sessions, client-side rendering, or DOM-bound extraction. Prefer fetchers (e.g., web_search or HTTP APIs) only for simple static content.

---

Best Practices

- Prefer specialized MCP tools over generic web search when a domain tool exists (e.g., Shodan vs generic search for exposed services).
- For time ranges: compute concrete dates and split long windows; aggregate results.
- Parallelize independent calls (e.g., Shodan + Censys + URLScan) and sequence dependent chains (e.g., Shodan results → Nuclei).
- Be conservative with destructive operations (e.g., obsidian_delete_file) and request confirmation when prompted.
- Respect server trust and confirmation policies; use allow-listing where appropriate.
