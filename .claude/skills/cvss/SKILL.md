---
name: cvss
description: Score a CVE using CVSS v4.0 metrics. Use when determining severity ratings, calculating impact scores, or choosing the right CVSS v4.0 vector string for a vulnerability.
---

# CVSS v4.0 Scoring

Reference: https://www.first.org/cvss/v4.0/specification-document

Read the current CVE record, analyze the vulnerability, and produce a CVSS v4.0 vector string with a brief rationale for each metric.

## Metric Reference

### Attack Vector (AV)
**Only use Network if the vulnerable component itself directly handles network traffic** (e.g. a web framework, HTTP server, network protocol library). A general-purpose library (e.g. a decimal math lib, JSON parser) is Local even if an app could theoretically expose it over the network.

| Value | Description |
|-------|-------------|
| N — Network | The vulnerable system is bound to the network stack and the set of possible attackers extends beyond the other options listed below, up to and including the entire Internet. |
| A — Adjacent | The vulnerable system is bound to a protocol stack, but the attack is limited at the protocol level to a logically adjacent topology (e.g. same subnet, Bluetooth, NFC). |
| L — Local | The vulnerable system is not bound to the network stack and the attacker's path is via read/write/execute capabilities. |
| P — Physical | The attack requires the attacker to physically touch or manipulate the vulnerable system. |

### Attack Complexity (AC)
| Value | Description |
|-------|-------------|
| L — Low | The attacker must take no measurable action to exploit the vulnerability. The attack requires no target-specific circumvention to exploit the vulnerability. |
| H — High | The successful attack depends on the evasion or circumvention of security-enhancing techniques in place that would otherwise hinder the attack. |

### Attack Requirements (AT)
| Value | Description |
|-------|-------------|
| N — None | The successful attack does not depend on the deployment and execution conditions of the vulnerable system. |
| P — Present | The successful attack depends on the presence of specific deployment and execution conditions of the vulnerable system that enable the attack. |

### Privileges Required (PR)
| Value | Description |
|-------|-------------|
| N — None | The attacker is unauthenticated prior to attack, and therefore does not require any access to settings or files. |
| L — Low | The attacker requires privileges that provide basic capabilities typically limited to settings and resources owned by a single low-privileged user. |
| H — High | The attacker requires privileges that provide significant (e.g., administrative) control over the vulnerable system. |

### User Interaction (UI)
| Value | Description |
|-------|-------------|
| N — None | The vulnerable system can be exploited without interaction from any human user, other than the attacker. |
| P — Passive | Successful exploitation requires limited interaction by the targeted user with the vulnerable system and the attacker's payload. |
| A — Active | Successful exploitation requires a targeted user to perform specific, conscious interactions with the vulnerable system and the attacker's payload. |

### Vulnerable System Impact (VC / VI / VA)
| Value | Description |
|-------|-------------|
| H — High | Total loss of confidentiality / integrity / availability within the Vulnerable System. |
| L — Low | Some loss, but the attacker does not have full control over what is accessed or modified / performance is reduced but service not fully denied. |
| N — None | No loss within the Vulnerable System. |

### Subsequent System Impact (SC / SI / SA)
Only set non-None if the vulnerability meaningfully impacts systems beyond the vulnerable component itself.

| Value | Description |
|-------|-------------|
| H — High | Total loss of confidentiality / integrity / availability within the Subsequent System. |
| L — Low | Some loss, but the attacker does not have full control over what is accessed or modified / performance is reduced but service not fully denied. |
| N — None | No loss within the Subsequent System, or all impact is constrained to the Vulnerable System. |

### Supplemental (optional, do not affect score)
| Metric | Values |
|--------|--------|
| Safety (S) | N=Negligible, P=Present |
| Automatable (AU) | N=No, Y=Yes |
| Recovery (R) | A=Automatic, U=User, I=Irrecoverable |
| Value Density (V) | D=Diffuse, C=Concentrated |
| Vulnerability Response Effort (RE) | L=Low, M=Moderate, H=High |
| Provider Urgency (U) | Clear, Green, Amber, Red |

## Steps

1. Read the CVE record to understand the vulnerability.
2. For each Base metric, choose the value and state a one-sentence rationale.
3. Assess Subsequent System Impact — only non-None if there is meaningful impact beyond the vulnerable component.
4. Consider Supplemental metrics if they add useful context.
5. Produce the vector string in the form:
   `CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_`
6. Run `scripts/cvss-score "<vector>"` to get the real numeric score and severity rating.
   Example: `scripts/cvss-score "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"`

## Output Format

Present:
- The vector string
- A short rationale table (metric → chosen value → reason)
- The score/severity from `scripts/cvss-score` filled into the JSON snippet ready to paste, e.g.:
  ```json
  {
    "cvssV4_0": {
      "attackVector": "NETWORK",
      "baseScore": 0.0,
      "baseSeverity": "UNKNOWN",
      "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
      "version": "4.0"
    },
    "format": "CVSS",
    "scenarios": [
      {
        "lang": "en",
        "value": "GENERAL"
      }
    ]
  }
  ```