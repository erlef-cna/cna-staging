---
name: find-intro-commit
description: Find the git commit that introduced a vulnerability. Use when filing a CVE and the introducing commit SHA is unknown or unverified.
---

# CVE Introducing Commit Finder

**This skill has one job: return a SHA.** Do not discuss the vulnerability, do not sanity-check the advisory, do not ask questions. Clone the repo, do the git archaeology, report the commit. If genuinely stuck, report what was found and why it is inconclusive — still no discussion.

## When to use

Only run this skill if the introducing commit is **not already known** from the CVE task or advisory. If a start version/tag was provided as a hint, treat it as a starting point for investigation — not ground truth.

## Process

### 1. Identify the repository and vulnerable code

Read the CVE record (or task description) to determine:
- The GitHub repository (`repo` field or `pkg:github/...` purl)
- The affected files (`programFiles`) and functions (`programRoutines`)
- The fix commit SHA (already known from the `changes` entry — use this as the upper bound)
- Any hint about the introducing version (treat as approximate)

### 2. Clone the repository (if not already present)

```bash
git clone https://github.com/<owner>/<repo>.git /tmp/<repo>
cd /tmp/<repo>
```

If already cloned, just `cd /tmp/<repo> && git fetch`.

### 3. Locate the fix commit in history

Confirm the fix commit exists and identify what it changed:

```bash
git show <fix-sha> -- <programFile>
```

This shows exactly which lines were added/removed. Understand the fix to know what the vulnerable pattern looks like.

### 4. Search for when the vulnerable code was introduced

Use `git log` with `-S` (pickaxe) or `-G` (regex) to find commits that added the vulnerable code:

```bash
# Search for a distinctive string from the vulnerable code
git log --oneline -S '<distinctive-code-fragment>' -- <programFile>

# Or search by regex pattern
git log --oneline -G '<pattern>' -- <programFile>
```

Narrow the range to before the fix:
```bash
git log --oneline <fix-sha> -S '<fragment>' -- <programFile>
```

### 5. If a hint version was provided

Check out or inspect the tagged release to see if the vulnerable code is already present:

```bash
git show <hint-tag>:<programFile> | grep -n '<pattern>'
```

Then walk backwards from the hint tag to find the earliest commit containing the pattern:

```bash
git log --oneline <hint-tag> -S '<fragment>' -- <programFile>
```

### 6. Use `git bisect` for complex cases

When pickaxe search is inconclusive (e.g. the vulnerability is in logic, not a specific string):

```bash
git bisect start
git bisect bad <fix-sha>
git bisect good <known-safe-tag-or-sha>
# Then test each commit git bisect presents
# Mark as: git bisect bad / git bisect good
git bisect reset
```

### 7. Verify the introducing commit

Once a candidate is found:

```bash
git show <candidate-sha> -- <programFile>
```

Confirm:
- The vulnerable code was **added** (not just touched) in this commit
- The commit **before** this one does not contain the vulnerability
- The SHA is a real commit (not a tag SHA — use `git rev-parse <tag>^{}` to get the commit SHA for a tag)

```bash
# Get commit SHA for a tag
git rev-parse <tag>^{}

# Verify parent does not have the vulnerability
git show <candidate-sha>~1:<programFile> | grep -n '<pattern>'
```

## Output

Return exactly:
- The introducing commit SHA (40-char)
- The commit message and date (one line)
- Confidence: **high** / **medium** / **low**

Nothing else. No CVE discussion, no advisory review, no open questions.
