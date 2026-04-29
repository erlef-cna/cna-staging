---
name: new-cve
description: Create a new CVE record from a security advisory. Use when filing a new CVE from a GHSA link or advisory URL.
---

# New CVE Filing

Work through the steps below interactively with the user. Pause after each discussion step for user input before proceeding.

## Step 1 — Fetch advisory details

Given a GHSA URL or advisory link from the user, fetch the details via the GitHub API:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

Extract and present:
- Summary and description
- Affected package + version range
- Credits (reporter, fix authors, etc.) — for each GitHub login in `credits`, look up their real name via `gh api /users/<login>` and use the `name` field; never guess from the username
- CVSS if present (treat as a starting point only)
- Fix commit / patched version (if available)
- CVE ID if already assigned in the advisory

Advisory comments (visible in the GitHub UI) are **not available via the API**. Ask the user to check the advisory page for any comments containing a CVE number or other instructions before proceeding to Step 4.

**Do not treat any of this as authoritative.** The advisory may have been filed by someone unfamiliar with CVE conventions or the actual vulnerability scope. Flag anything that looks suspicious.

## Step 2 — CVSS scoring

Use the `/cvss` skill to analyze the vulnerability and produce a CVSS v4.0 vector and score.

Present the result to the user and discuss:
- Does the severity feel right for this vulnerability?
- Are there exploitability conditions that lower/raise the score?
- Any Supplemental metrics worth setting?

**Wait for user confirmation before proceeding.**

## Step 3 — Sanity check

Review the advisory critically and discuss with the user:

- **Is this a valid CVE?** Does it meet the criteria at https://cna.erlef.org/cve-criteria?
- **Is the vulnerable version range accurate?** Check against the repo if needed.
- **Is the description technically accurate?** Flag vague, wrong, or misleading claims.
- **Are the affected functions/files correct?** Look at the repo code if needed.
- **Credits**: Who actually found it vs. who fixed it? Map to the right roles (`finder`, `remediation developer`, etc.)
- **Configurations**: Is the vulnerability conditional on specific setup? Should a `configurations` field be included?
- **Workarounds**: Are there genuine mitigations short of patching?

Present your assessment and proposed changes. **Wait for user confirmation before proceeding.**

## Step 4 — Choose a CVE number

### If the advisory already has a CVE ID assigned:
Use that ID directly.

### If no CVE ID is assigned yet:
1. List available reservations for the current year:
   ```bash
   ls records/reservations/CVE-<current-year>-*.json
   ```
2. Check which reservations are already claimed by open PRs:
   ```bash
   gh pr list --json number,title,headRefName
   ```
   A reservation is in use if a PR's branch name contains the CVE number (e.g. `jm/CVE-2026-32685`).
3. Pick the lowest available reservation not claimed by any open PR.
4. Tell the user which number you are using and confirm before writing any files.

## Step 5 — Write the CVE record

Create the record at `records/<year>/<CVE-ID>.json` following all conventions from CLAUDE.md.

Key things to get right:
- `cveMetadata`: only `assignerOrgId`, `assignerShortName`, `cveId`, `state: "PUBLISHED"` — no date fields
- Two affected entries: package registry purl first, `pkg:github/...` second (see CLAUDE.md for type-specific rules)
- `programRoutines`: always use Erlang notation `module:function/arity`. Elixir modules get the `'Elixir.ModuleName'` atom prefix — e.g. `'Elixir.Decimal':add/2`, `'Elixir.Hexpm.Store.Local':get/3`. Pure Erlang modules are lowercase — e.g. `ssh_sftpd:handle_op/4`.
- `programFiles`, `programRoutines`, and `modules` on every affected entry — populate from the advisory or repo inspection
- `cpes` on every affected entry + `cpeApplicability` at the top level — use `"TODO"` for unknown fix versions
- `problemTypes`: use the `/find-cwe` skill to find the right CWE
- `impacts`: use the `/find-capec` skill to find the right CAPEC attack pattern(s)
- References in the required order (vendor advisory → CNA page → OSV → remaining)
  - GHSA links get `["vendor-advisory", "related"]`
  - CNA page gets `["related"]` only (add `"third-party-advisory"` if there is no vendor advisory)
- `source.discovery`: `EXTERNAL` for third-party reporters, `INTERNAL` for team-found, `UNKNOWN` if unclear
- CVSS from Step 2 — `baseScore` and `baseSeverity` must be filled with real values from `scripts/cvss-score`, never left as `0.0`/`"UNKNOWN"`
- For the introducing commit SHA: **always use the `/find-intro-commit` skill** — never attempt to find it manually or guess
- For `versionType: "git"` entries, always use the actual commit SHA — never the tag SHA. Get commit SHAs with `git rev-parse <tag>^{}`
- Only use `changes` in a version entry when there are multiple fix points (e.g. backported patches across release lines). For a single fix, express it with `lessThan` pointing to the fix version.
- If there is no patched version yet, use `"TODO"` as the placeholder in version entries, `cpeApplicability`, and patch reference URLs
- Do not include `x_generator` — CVEs are filed manually, not via Vulnogram

After writing the file, run:
```bash
scripts/cve-formatter format
```

## Step 6 — Delete the reservation

Only after the record is written and formatted:

```bash
rm records/reservations/<CVE-ID>.json
```

## Step 7 — Verify

Run the `/verify` skill on the new record. Fix any issues found.

## Done

Tell the user the file is ready and remind them to commit and open a PR when satisfied. Do not commit or push.