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
- Credits (reporter, fix authors, etc.) — for each GitHub login in `credits`, look up their real name via `gh api /users/<login>` and use the `name` field; never guess from the username. Known canonical-name overrides:
  - `IngelaAndin` → `Ingela Anderton Andin` (the GitHub `name` field returns "Ingela Andin", but past records in this repo use the full name)
  - `maennchen` (Jonatan Männchen) → `Jonatan Männchen / EEF` (when acting in his EEF capacity, e.g. as `analyst` or coordinator on EEF-handled advisories — append ` / EEF`)
  - `u3s` → `Jakub Witczak` (the GitHub `name` field only returns "Kuba")
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

Do not look up the introducing commit here. That happens in Step 5 via `/find-intro-commit`.

## Step 4 — Choose a CVE number

### If the advisory already has a CVE ID assigned:
Use that ID directly.

### If no CVE ID is assigned yet:
1. Run the helper script to find the next free reservation:
   ```bash
   scripts/next-free-cve
   ```
   This checks all `RESERVED` reservations for the current year and excludes any already claimed by open PRs. It prints the lowest free CVE ID, or exits with an error if none are available.
2. Tell the user which number you are using and confirm before writing any files.

## Step 5 — Write the CVE record

Create the record at `records/<year>/<CVE-ID>.json` following all conventions from CLAUDE.md.

### Generating `affected` and `cpeApplicability` for erlang/otp and elixir-lang/elixir

For CVEs in `erlang/otp` or `elixir-lang/elixir`, you **must** generate the `affected` and `cpeApplicability` blocks with `scripts/gen-affected` rather than writing them by hand. The script handles intro/fix release lookup, per-major or per-minor chaining of cpeApplicability ranges, single vs multi-fix shape, programFiles path stripping, packageURL formatting, and CPE wiring.

```bash
scripts/gen-affected <erlang|elixir> \
  --intro <intro-SHA-from-/find-intro-commit> \
  [--fix <fix-SHA>]... \
  --path <repo-relative-path> [--path ...] \
  [--module <name>]... \
  [--routine '<module:fun/arity>']...
```

Notes:
- `--path` is the repo-relative source path (e.g. `lib/ssh/src/ssh_auth.erl`, `lib/elixir/lib/version.ex`). The script derives the OTP app or Elixir sub-app from the path and strips the prefix for the library-relative entry.
- Pass each affected `--module` and `--routine` exactly as it should appear in the record (Elixir modules need the `'Elixir.ModuleName'` atom prefix; routines use `module:function/arity`).
- Multiple `--fix` SHAs are allowed (one per maintained release line). Omit `--fix` entirely when no patch is published yet; the script emits `TODO<major>` (or a single `TODO` for Elixir) so the record validates while the fix is pending.
- Output is a JSON object with `affected` and `cpeApplicability` keys; paste those two keys into the record. Do not re-derive the same structures by hand.
- If the script can't represent the case (extraction across apps, hex packages, gleam, fully manual ranges), fall back to the bullets below and explain why in the PR.

### Other key things to get right

- `cveMetadata`: only `assignerOrgId`, `assignerShortName`, `cveId`, `state: "PUBLISHED"` — no date fields
- Two affected entries: package registry purl first, `pkg:github/...` second (see CLAUDE.md for type-specific rules). Edge case: the hex package manager itself uses `pkg:otp/hex?repository_url=...&vcs_url=...` (not `pkg:hex/hex` — hex cannot list itself in its own registry), but `versionType` stays `"semver"` because hex follows real semver.
- `programRoutines`: always use Erlang notation `module:function/arity`. Elixir modules get the `'Elixir.ModuleName'` atom prefix — e.g. `'Elixir.Decimal':add/2`, `'Elixir.Hexpm.Store.Local':get/3`. Pure Erlang modules are lowercase — e.g. `ssh_sftpd:handle_op/4`.
- `programRoutines` lists the routines that are *vulnerable*, not every routine the fix commit happens to touch. Skip bookkeeping helpers (changelog writers, version bumps, test-only changes) that the patch incidentally modifies.
- **Cross-language reachability for NIFs/BIFs.** `modules` and `programRoutines` exist so a consumer can answer "does my code reach the bug?" When the vulnerable code lives behind a language boundary (Rust NIF, C BIF, port driver), list **both sides** of the call chain on every affected entry:
  - The implementing module/function (e.g. Rust crate `mdex_native_nif`, function `mdex_native_nif::lumis_adapter::LumisAdapter::parse_highlight_lines`).
  - The Erlang/Elixir module(s) and function(s) callers actually invoke (e.g. `'Elixir.MDEx'` and `'Elixir.MDEx':to_html/2`, or the NIF binding wrapper like `'Elixir.MDEx.Native':document_to_html_with_options/2`).
- **Extraction packages.** If vulnerable code in package A was later extracted into a new package B (still in the vulnerable versions of A), treat them as separate affected products:
  - A's upper bound is the extraction commit / version (the bug is no longer present in A after the extraction).
  - B is listed as a separate affected entry, with its own version range starting at its first release.
  - The patch reference points only at B's fix commit, since A is no longer where a fix would land.
- `programFiles`, `programRoutines`, and `modules` on every affected entry — populate from the advisory or repo inspection
- `defaultStatus` on each affected entry must be `"unaffected"` when versions are bounded. `"affected"` implicitly marks every unlisted version (older releases, post-fix releases) as vulnerable, which is almost never what we mean.
- `repo` URL must not have a `.git` suffix (for GitHub) and must match on every affected entry for the same project (e.g. always `https://github.com/<owner>/<repo>`).
- `cpes` on every affected entry + `cpeApplicability` at the top level — use `"TODO"` for unknown fix versions
- `cpeApplicability` operator orientation: outer node is `"OR"` (any of the listed products can match), each inner `cpeMatch` group is `"AND"` (a match within that product requires all criteria). Do not invert these.
- `problemTypes`: use the `/find-cwe` skill to find the right CWE
- `impacts`: use the `/find-capec` skill to find the right CAPEC attack pattern(s)
- References in the required order (vendor advisory → CNA page → OSV → remaining)
  - GHSA links get `["vendor-advisory", "related"]`
  - CNA page gets `["related"]` only (add `"third-party-advisory"` if there is no vendor advisory)
- `source.discovery`: `EXTERNAL` for third-party reporters, `INTERNAL` for team-found, `UNKNOWN` if unclear
- CVSS from Step 2 — `baseScore` and `baseSeverity` must be filled with real values from `scripts/cvss-score`, never left as `0.0`/`"UNKNOWN"`
- For the introducing commit SHA: **always use the `/find-intro-commit` skill** — never attempt to find it manually or guess
- Cross-check the introducing commit against the advisory's "first affected version": once `/find-intro-commit` returns a SHA, run `git tag --contains <sha>` and confirm that the earliest reachable tag matches what the advisory claims. Advisories sometimes list the wrong first version. If they disagree, trust the SHA + tag containment and update the version range accordingly.
- For `versionType: "git"` entries, always use the actual commit SHA — never the tag SHA. The introducing `version` comes from `/find-intro-commit` (a commit that predates any release tag). The `lessThan` fix SHA comes from the patch commit, not from `git rev-parse <tag>^{}`.
- Only use `changes` in a version entry when there are multiple fix points (e.g. backported patches across release lines). For a single fix, express it with `lessThan` pointing to the fix version.
- If there is no patched version yet, use `"TODO"` as the placeholder in version entries, `cpeApplicability`, patch reference URLs, and in the description text (e.g. "from 0.6.0 before TODO")
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