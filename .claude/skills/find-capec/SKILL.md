---
name: find-capec
description: Find the right CAPEC ID for a vulnerability. Use when filing a CVE and the CAPEC attack pattern is unknown or needs verification.
---

# CAPEC Finder

Find the most appropriate CAPEC attack pattern(s) for the vulnerability and return the entries ready to paste into the CVE record.

## Search

Use the WebSearch tool to find matching CAPEC entries — e.g. `site:capec.mitre.org path traversal`, `site:capec.mitre.org resource exhaustion`.

For a direct ID lookup, use the WebFetch tool:
```
https://capec.mitre.org/data/definitions/<ID>.html
```

Pick the most specific pattern that accurately describes *how* the attack works, not just the outcome. Multiple CAPECs are fine when the vulnerability can be exploited via distinct attack techniques (e.g. both relative and absolute path traversal, as in CVE-2026-32146).

## Output

Return the snippet ready to paste into `impacts`:

```json
[
  {
    "capecId": "CAPEC-<ID>",
    "descriptions": [
      {
        "lang": "en",
        "value": "CAPEC-<ID> <Name>"
      }
    ]
  }
]
```
