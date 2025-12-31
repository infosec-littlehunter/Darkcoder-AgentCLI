#!/usr/bin/env python3

# Column widths - increased to fit content
scenario_w = 32
primary_w = 50
secondary_w = 40
rationale_w = 65

# Data rows
rows = [
    ("Reconnaissance & Enumeration", 
     "Kali MCP (subfinder_scan, amass_scan)", 
     "Browser MCP (browser_navigate)", 
     "Kali tools for discovery, Browser for verification"),
    ("Vulnerability Scanning", 
     "Kali MCP (nuclei_scan, nikto_scan)", 
     "Burp MCP (get_proxy_http_history)", 
     "Automated scanning + manual verification"),
    ("Authentication Testing", 
     "Browser MCP (browser_type, browser_click)", 
     "Burp MCP (send_http1_request)", 
     "Browser for UI flows, Burp for API/auth bypass"),
    ("XSS Testing", 
     "Browser MCP (browser_type, chrome_inject_script)", 
     "Kali MCP (dalfox_scan)", 
     "Browser for context-aware payloads, Dalfox for automation"),
    ("SQL Injection", 
     "Kali MCP (sqlmap_scan, ghauri_scan)", 
     "Burp MCP (create_repeater_tab)", 
     "Automated detection + manual exploitation"),
    ("API Testing", 
     "Burp MCP (send_http1_request, send_http2_request)", 
     "Browser MCP (chrome_network_request)", 
     "Burp for raw API calls, Browser for token context"),
    ("Directory Brute-forcing", 
     "Kali MCP (gobuster_scan, ffuf_scan)", 
     "Browser MCP (browser_navigate)", 
     "Fast enumeration + visual verification"),
    ("JWT/Token Manipulation", 
     "Kali MCP (jwt_tool_scan)", 
     "Browser MCP (chrome_inject_script)", 
     "Token analysis + browser context manipulation"),
    ("Command Injection", 
     "Kali MCP (commix_scan)", 
     "Burp MCP (set_active_editor_contents)", 
     "Automated exploitation + manual payload refinement"),
    ("SSRF Testing", 
     "Kali MCP (ssrfmap_scan)", 
     "Browser MCP (chrome_network_request)", 
     "SSRF detection + browser-based callback verification"),
    ("GraphQL Testing", 
     "Kali MCP (graphqlmap_scan)", 
     "Burp MCP (send_http1_request)", 
     "GraphQL-specific testing + general HTTP manipulation"),
    ("WordPress Assessment", 
     "Kali MCP (wpscan_analyze)", 
     "Browser MCP (browser_navigate)", 
     "WordPress-specific scanning + theme/plugin inspection"),
]

def pad(text, width):
    """Pad text to exact width with spaces."""
    if len(text) > width:
        # Truncate with ellipsis
        return text[:width-3] + "..."
    return text + " " * (width - len(text))

# Top border
top = "┌" + "─" * scenario_w + "┬" + "─" * primary_w + "┬" + "─" * secondary_w + "┬" + "─" * rationale_w + "┐"
# Header separator
mid = "├" + "─" * scenario_w + "┼" + "─" * primary_w + "┼" + "─" * secondary_w + "┼" + "─" * rationale_w + "┤"
# Bottom border
bot = "└" + "─" * scenario_w + "┴" + "─" * primary_w + "┴" + "─" * secondary_w + "┴" + "─" * rationale_w + "┘"

# Header row
header = "│ " + pad("Scenario", scenario_w) + " │ " + pad("Primary Tool", primary_w) + " │ " + pad("Secondary Tool", secondary_w) + " │ " + pad("Rationale", rationale_w) + " │"

# Build table
lines = []
lines.append(top)
lines.append(header)
lines.append(mid)
for scenario, primary, secondary, rationale in rows:
    row = "│ " + pad(scenario, scenario_w) + " │ " + pad(primary, primary_w) + " │ " + pad(secondary, secondary_w) + " │ " + pad(rationale, rationale_w) + " │"
    lines.append(row)
lines.append(bot)

# Decision flow
decision_flow = """
  SCENARIO-BASED DECISION TREE:

  1. IF (Target requires JavaScript execution or visual verification) → Start with Browser MCP
  2. IF (Target has API endpoints or needs request manipulation) → Start with Burp MCP
  3. IF (Target needs reconnaissance or automated scanning) → Start with Kali MCP
  4. IF (Complex authentication flows) → Combine Browser MCP (UI) + Burp MCP (API)
  5. IF (Large-scale enumeration) → Combine Kali MCP (scanning) + Browser MCP (verification)
  6. IF (Vulnerability validation) → Combine Kali MCP (detection) + Burp MCP (exploitation)
  7. IF (Real-time adaptation needed) → Use Browser MCP for monitoring and dynamic adjustment
  8. IF (Stealth required) → Use Kali MCP with evasion techniques + Browser MCP for low-noise verification
"""

# Combine
full_block = "\n".join(lines) + decision_flow
print(full_block)