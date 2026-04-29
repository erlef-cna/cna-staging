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
- [ ] `cveMetadata` contains only: `assignerOrgId`, `assignerShortName`, `cveId`, `state`
- [ ] `cveMetadata.state` is `"PUBLISHED"`
- [ ] No date fields in `cveMetadata` (`datePublished`, `dateReserved`, `dateRejected`, `dateUpdated`)

### programRoutines
- [ ] All `programRoutines` use Erlang notation `module:function/arity` — Elixir modules use the `'Elixir.ModuleName'` atom prefix (e.g. `'Elixir.Decimal':add/2`), not Elixir dot notation (`Decimal.add/2`)
- [ ] No `x_generator` field present (CVEs are filed manually, not via Vulnogram)

### Descriptions
- [ ] Plain text description (`value`) is present
- [ ] HTML description (`supportingMedia` with `type: "text/html"`) is present
- [ ] HTML uses `<tt>` for code/paths and `<p>` for paragraphs

### Affected Entries
- [ ] No version entry uses `versionType: "purl"`
- [ ] Git `changes` entries use the fix commit SHA (not a release tag SHA)
- [ ] `cpes` are present on each affected entry
- [ ] `cpeApplicability` is present at the top level and mirrors the version ranges from the affected entries

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

### CVSS
- [ ] `baseScore` is not `0.0` (dummy value left unfilled)

## Output

Report a summary: list each failed check with the specific problem and fix applied (or needed). If everything passes, confirm with "All checks passed."