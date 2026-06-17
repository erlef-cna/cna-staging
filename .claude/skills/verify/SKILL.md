---
name: verify
description: Verify a CVE record for correctness. Use when checking a CVE before committing, reviewing conventions, or validating schema and formatting.
---

# CVE Verifier

Reference: https://cna.erlef.org/cve-criteria

Run all checks below on the CVE record(s) specified by the user (or the current working CVE if none specified). Fix any issues found, then confirm everything passes.

## Step 1 — Format Check

```
scripts/cve-formatter check-formatted
```

If it fails, run `scripts/cve-formatter format` to fix, then re-check.

## Step 2 — JSON Schema Validation

```
scripts/cve-schema-validate validate <file>
```

Fix any schema errors before proceeding.

## Step 3 — cvelint

```
cvelint -ignore E007 records
```

Fix any lint errors before proceeding.

## Step 4 — Convention Checklist

Read the CVE record and verify each item below. Report PASS/FAIL for each.

### Metadata
- [ ] `cveMetadata` contains `assignerOrgId`, `assignerShortName`, `cveId`, and `state` — date fields (`datePublished`, `dateReserved`, `dateRejected`, `dateUpdated`) are set externally and are fine if present; do not remove them
- [ ] `cveMetadata.state` is `"PUBLISHED"`

### programRoutines and modules
- [ ] All `programRoutines` use Erlang notation `module:function/arity` — Elixir modules use the `'Elixir.ModuleName'` atom prefix (e.g. `'Elixir.Decimal':add/2`), not Elixir dot notation (`Decimal.add/2`)
- [ ] `programRoutines` lists vulnerable routines only — no bookkeeping helpers (changelog writers, version bumps, test-only changes) that the fix commit happens to touch
- [ ] Cross-language reachability: when the vulnerable code is behind a language boundary (Rust NIF, C BIF, port driver), every affected entry lists **both sides** of the call chain — the implementing function (e.g. `mdex_native_nif::lumis_adapter::LumisAdapter::parse_highlight_lines`) *and* the Erlang/Elixir module(s) + function(s) callers invoke (e.g. `'Elixir.MDEx'` + `'Elixir.MDEx':to_html/2`). `modules` lists the analogous module names on both sides.
- [ ] No `x_generator` field present — it may appear in records that were published and then fetched back; ignore it if present, do not remove it

### Descriptions
- [ ] Plain text description (`value`) is present
- [ ] HTML description (`supportingMedia` with `type: "text/html"`) is present
- [ ] HTML uses `<tt>` for code/paths and `<p>` for paragraphs
- [ ] Description does not mention other CVE IDs — describe the vulnerability class by name instead
- [ ] The "This issue affects …" sentence ends with a real version number, not `TODO` — if the fix version is not yet known, use `before TODO` as a placeholder (e.g. `from 1.2.3 before TODO`)

### Configurations
- [ ] If `configurations` is present, each entry includes both plain text (`value`) and HTML (`supportingMedia` with `type: "text/html"`)

### Affected Entries
- [ ] No version entry uses `versionType: "purl"`
- [ ] Git `changes` entries use the fix commit SHA (not a release tag SHA)
- [ ] `defaultStatus` is `"unaffected"` on every entry whose `versions` array bounds a range (lessThan / lessThanOrEqual). `"affected"` implicitly marks unlisted versions as vulnerable and is almost always wrong.
- [ ] `repo` URL has no `.git` suffix on GitHub entries and is consistent across all entries for the same project
- [ ] The `pkg:github/...` (or other source-repo) entry contains only `versionType: "git"` blocks — no duplicate `semver` block (those belong on the package-registry entry)
- [ ] `cpes` are present on each affected entry
- [ ] `cpeApplicability` is present at the top level and mirrors the version ranges from the affected entries
- [ ] `cpeApplicability` operator orientation: outer node is `"OR"`, each inner `cpeMatch` group is `"AND"`. Do not invert.

Detect the CVE type from the `packageURL` of the first affected entry and apply the corresponding rules:

**OTP CVEs** (first entry `pkg:otp/<lib>`):
- [ ] Exactly two affected entries
- [ ] First entry: `pkg:otp/<lib>`, versions with `versionType: "otp"`
- [ ] Second entry: `pkg:github/erlang/otp`, with `versionType: "otp"` blocks followed by `versionType: "git"` blocks
- [ ] `programFiles` in the first (`pkg:otp/<lib>`) entry use paths relative to the library root (e.g. `src/ssh_sftpd.erl`) — not the full repo path
- [ ] `programFiles` in the second (`pkg:github/erlang/otp`) entry use the full repo-relative path including the `lib/<app>/` prefix (e.g. `lib/ssh/src/ssh_sftpd.erl`)
- [ ] Each affected entry has `programFiles`, `programRoutines`, and `modules`

**Gleam compiler CVEs** (first entry `pkg:sid/gleam.run/gleam`):
- [ ] First entry: `pkg:sid/gleam.run/gleam`, versions with `versionType: "semver"`
- [ ] Second entry: `pkg:github/gleam-lang/gleam`, with both `versionType: "semver"` and `versionType: "git"` version blocks
- [ ] If Docker images are affected: third entry `pkg:oci/gleam?repository_url=ghcr.io/gleam-lang` with `versionType: "other"` entries per image variant
- [ ] Each affected entry has `programFiles`, `programRoutines`, and `modules`

**Gleam package CVEs** (first entry `pkg:hex/<name>`, vendor/product references Gleam ecosystem):
- [ ] Exactly two affected entries
- [ ] First entry: `pkg:hex/<name>`, versions with `versionType: "semver"`
- [ ] Second entry: `pkg:github/<owner>/<repo>`, versions with `versionType: "git"`
- [ ] Each affected entry has `programFiles`, `programRoutines`, and `modules`

**Other Hex package CVEs** (first entry `pkg:hex/<name>`):
- [ ] Exactly two affected entries
- [ ] First entry: `pkg:hex/<name>`, versions with `versionType: "semver"`
- [ ] Second entry: `pkg:github/<owner>/<repo>`, versions with `versionType: "git"`
- [ ] Each affected entry has `programFiles`, `programRoutines`, and `modules`

### Cross-check against the advisory

Find the GHSA URL in the references (first entry tagged `vendor-advisory`), then re-fetch it:

```bash
gh api /repos/<owner>/<repo>/security-advisories/<ghsa-id>
```

- [ ] **Stale TODOs.** Every `"TODO"` in the record (version `lessThan`, `cpeApplicability.versionEndExcluding`, description "before TODO", patch reference URL) is still a `TODO` in the advisory's `patched_versions`. If the advisory has a real fix version and the record still says `TODO`, fix it.
- [ ] **Version ranges match.** Each affected entry's semver range matches the advisory's `vulnerable_version_range` for that package. Investigate any mismatch before trusting either side.
- [ ] **Intro commit reachability.** For each `versionType: "git"` introducing SHA, run `git tag --contains <sha>` against the repo. The earliest reachable tag should match the first affected semver version. If it doesn't, the intro commit or the first-version claim is wrong — diagnose before proceeding.
- [ ] **Credits coverage.** Every credit in the advisory's `credits` array appears in the record with the right role (`reporter` → `finder`, `remediation_developer` → `remediation developer`, `coordinator` → `analyst`, etc.). Do not skip credits with state `pending`.

### Source
- [ ] `source.discovery` is one of `"EXTERNAL"`, `"INTERNAL"`, `"UNKNOWN"`

### Credits
- [ ] Reporters use role `"finder"`
- [ ] Fix authors use role `"remediation developer"`
- [ ] Reviewers use role `"remediation reviewer"`
- [ ] Analysts use role `"analyst"`

### Workarounds
- [ ] No workaround entry says "apply patch" or "apply the patch"
- [ ] No workaround entry says "There are no workarounds"
- [ ] If no genuine workarounds: `workarounds` field is omitted entirely

### References (in order)
- [ ] First reference: vendor advisory with tag `["vendor-advisory"]` (or `["vendor-advisory", "related"]` for GHSA)
- [ ] Second reference: `https://cna.erlef.org/cves/CVE-<num>.html` with tag `["related"]` (add `"third-party-advisory"` if no vendor advisory)
- [ ] Third reference: `https://osv.dev/vulnerability/EEF-CVE-<num>` with tag `["related"]`
- [ ] For OTP CVEs: `https://www.erlang.org/doc/system/versions.html#order-of-versions` with tag `["x_version-scheme"]` present
- [ ] At least one reference with tag `"patch"` is present — if the patch commit is not yet known, use a placeholder URL ending in `/TODO` (e.g. `https://github.com/<owner>/<repo>/commit/TODO`). The only exception is CVEs being published intentionally without a patch; if no patch reference is present at all, confirm with the user before proceeding.

### CVSS
- [ ] `baseScore` is not `0.0` (dummy value left unfilled)

## Output

Report a summary: list each failed check with the specific problem and fix applied (or needed). If everything passes, confirm with "All checks passed."