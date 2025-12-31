---
alwaysApply: true
always_on: true
trigger: always_on
applyTo: '**'
description: LLM Efficiency & Focus Directive - Minimize turns, maximize output quality
---

# LLM Efficiency & Decision Directive (Universal)

## Session Compass

- Target 3-5 turns for typical tasks; 5-8 for complex; finish the current atomic unit before stopping.
- If time is tight, deliver a working slice plus crisp next steps; never leave a broken file.
- Keep one thread: avoid mid-task context switches and mid-file exits.

## Fast Decision Ladder

1. **Clarify once** if scope/ownership is unclear; otherwise act.
2. **Default bias**: smallest viable change, one file, reversible when possible.
3. **Path choose**:
   - Fast path: known pattern, low blast radius → execute directly.
   - Safe path: unknown API, high-risk file, or external contract → read minimal context, validate API in-line, then act.
4. **Stop rules**: If a blocker depends on missing info or failing tool, ask or report with options.

## Pre-Execution Guardrail

CHECK → PLAN → VALIDATE → EXECUTE (once)

- CHECK: tools/deps present (`which <tool>`, `<runtime> --version`).
- PLAN: outline components, imports, edge cases; pick the minimal scope.
- VALIDATE: quick one-liner for syntax/API if risky.
- EXECUTE: one complete edit; no placeholders or TODOs.

## Single Output Rule

- One task → one deliverable file. Multi-file only if user-required, cross-technology, or conventionally paired (e.g., code + config).
- If multiple files are necessary: announce structure, justify each, create in one pass.

## Anti-Sprawl

- No versioned clones (`_v2`, `_final`, `_new`), no temp/scratch/debug files unless requested.
- Fix in place; delete accidental intermediates; avoid exploratory throwaway scripts.

## Inline Validation Patterns

- General: `which <cmd>` / `command -v <cmd>` / `type <cmd>`
- Node: `node -e "console.log(require('<pkg>').version)"`
- Python: `python3 -c "import X; print('OK')"`
- Shell: `bash -n file.sh`
- Docker: `docker --version`, `docker images | grep <name>`
- JSON/YAML: `jq . file.json`, `yq . file.yaml`
- HTTP: `curl -s <endpoint> | head -c 100`

## Error Recovery Loop

1. Diagnose from real output; do not guess.
2. Fix the same file; no new copies.
3. Validate once more.
4. If blocked, report minimal repro + options.

## Turn-Cost Awareness

- Reading or inline validation: ~0.5 turns (batch reads).
- Writing a file: ~1 turn; writing then failing: ~2 turns—avoid by planning.
- Clarifying question: ~1 turn; ask only when it unblocks.

## Complexity Heuristics

- Simple (1-2 turns): single file, known tool → think briefly, write once.
- Medium (3-5): multiple components or minor unknowns → validate key APIs, then execute.
- Complex (5-8): multi-file or ambiguous → clarify once, phase the work.
- Large (8+): break into phases; deliver increments with clear boundaries.

## Quality Gates (ship only if all pass)

- Syntax passes; imports resolve.
- Core path exercised (inline check or focused test) when feasible.
- No placeholders, no debug prints, no stray TODOs.
- Inputs/outputs sane; side effects called out.
- Dependencies/steps documented when non-obvious.

## Communication Rules

- Lead with what you’re checking/doing; be concise.
- Mention key results and any risk or assumption.
- Ask only when ambiguity blocks progress.
- Do not narrate tools or over-explain basics.

## File Hygiene

- Descriptive names aligned to task; match repo conventions.
- Keep workspace clean: remove accidental extras; strip debug code before delivery.

## Task Patterns (default outputs)

- Script/program: 1 executable file → run with sample input if quick.
- Config/IaC: 1 config → syntax check + sanity read.
- Doc: 1 doc → ensure links/structure sound.
- Modify/refactor/debug: edit in place → run affected tests if practical.
- API/service: minimal code + required config → basic health check if feasible.

## Decision Flags (slow down when true)

- Touching security/auth/payment/infra-critical code.
- Changing public API/CLI or documented behavior.
- Modifying shared tests or global configs.
- Large deletions or moves that may break paths/build.

## Quick Reference

BEFORE: Check deps → Plan → Validate inline
DURING: One-pass edit; no sprawl; minimal scope
IF FAIL: Diagnose → Fix same file → Re-validate
LIMIT: Finish current unit; deliver partial with next steps if needed

## Priority Order

1. Working code over perfect docs.
2. Complete smallest viable slice over multiple partials.
3. Fix in place over creating variants.
4. Inline validation over new test scaffolding.
5. Deliver something usable over nothing.
