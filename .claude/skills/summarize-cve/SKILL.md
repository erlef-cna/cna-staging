---
name: summarize-cve
description: Produce a concise technical markdown summary of a CVE. Use when preparing a human-readable write-up from a local CVE record, optionally enriched with the GHSA advisory.
---

# CVE Summarizer

Produce a concise technical markdown summary of a CVE. The output is for a security-oriented audience, not an end-user advisory.

## Step 1 — Load the CVE record

Read the local CVE record (path provided by the user, or find it under `records/<year>/<CVE-ID>.json`).

Extract:
- Title and CVE ID
- Description (plain text value)
- Affected package, version range, programFiles, programRoutines
- CVSS score and vector
- References (look for a GHSA link in the vendor-advisory reference)
- Credits
- Configurations / workarounds if present
- Patch commit URL(s) from references tagged `"patch"`
- Introduction commit SHA from the git `changes` version entry (`version` field, `versionType: "git"`)

## Step 2 — Fetch the GHSA (if present)

If the references contain a GitHub Security Advisory URL (pattern: `github.com/<owner>/<repo>/security/advisories/GHSA-...`), fetch it via the GitHub API:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

Use the GHSA `description` field for additional technical detail — the raw advisory often has richer detail than the CVE description. Do not treat it as authoritative; use it as supplemental context.

## Step 3 — Produce the markdown summary

Write the output to `/tmp/cve-summary-<CVE-ID>.md`, then run `code /tmp/cve-summary-<CVE-ID>.md` to open it in the editor. Do not print the content to the terminal.

Output exactly the following sections. All section headings must be H3 (`###`), never H2. Keep each section concise. Do not include code blocks or source-code snippets anywhere in the output — describe the relevant code in prose, referencing file and function names. Use `TODO` for any value that is not yet known, both in URLs and in prose (e.g. `from 0.1.0 before TODO`); do not paraphrase as "latest release at time of filing" or similar.

---

### Summary

One short paragraph: what the vulnerability is, what it allows, and who can trigger it. No bullet points.

### Details

Technical deep-dive, structured with bold sub-headings if the vulnerability is a multi-step chain (e.g. **1. Input handling**, **2. Unsafe processing**, **3. Execution**). Include relevant file names and function names. Do not include code blocks. Omit filler.

### PoC

Numbered steps: the minimum steps to reproduce. Not a complete working exploit — just the attack path. Skip setup boilerplate unless it is non-obvious.

### Impact

One or two sentences describing the user-visible consequences of the vulnerability (what an attacker can do, who is affected in practical terms). Do not include affected version ranges (they live in the structured fields), do not include the CVSS score or severity, do not explain CVSS metric choices, and never write "no fix available" — CVEs are only published once a fix exists.

### References

A flat list of relevant links in this order:
1. Introduction commit (if known from the `version` field of the git version entry — use `TODO` if absent)
2. Patch commit(s) (from `"patch"`-tagged references — use `TODO` if not yet known)
3. Any other references that add genuinely useful context (e.g. upstream bug reports, related write-ups, documentation pages)

Never include the CNA advisory page (`cna.erlef.org/cves/...`), the CVE.org record, the GHSA link, or the OSV link — those are aggregator URLs that just point back at this same data.

Use this format for each line:
```
* Label: <URL>
```

---

## Notes

- Do not include CVSS vector strings in the output — the Impact section prose is enough.
- Do not add a "Credits" section unless the user asks.
- Do not add a "Workarounds" or "Configurations" section unless the CVE has non-trivial ones.
- Dates are not needed in the summary.
- Keep the total length roughly comparable to the example: a few tight paragraphs, not a wall of text.