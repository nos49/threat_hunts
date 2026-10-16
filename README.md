# Threat Hunting Reports

A collection of threat hunting investigations completed in a cyber range environment. Each hunt is documented as a structured report covering the trigger, methodology, KQL queries, findings, indicators of compromise, MITRE ATT&CK mapping, and recommendations.

The goal of this repo is to practice and show a repeatable, evidence-driven approach to threat hunting: start with a hypothesis, follow the data, back every claim with logs, and clearly state what the evidence does and does not prove.

---

## Table of Contents

- [Hunt Reports](#hunt-reports)
- [Report Structure](#report-structure)
- [Tools Used](#tools-used)
- [Skills Demonstrated](#skills-demonstrated)
- [Disclaimer](#disclaimer)

---

## Hunt Reports

| # | Hunt | Summary | Platform | Key Techniques | Severity | Status |
|---|---|---|---|---|---|---|
| 1 | [Scattered Invoice](./Scattered-Invoice/README.md) | MFA fatigue account takeover leading to inbox rule persistence and a thread-hijacked business email compromise against a finance team | Microsoft Sentinel | T1621, T1078.004, T1114.003, T1564.008, T1534 | High | Complete |

---

## Report Structure

Every report follows the same template, adapted from The Threat Hunter's Report Template (Hunt.io) and aligned with MITRE ATT&CK and the SANS Threat Hunting Methodology.

| Section | What It Covers |
|---|---|
| Executive Summary | Purpose, scope, and plain-language summary of findings |
| 1. Hunt Details | Dates, analyst, hunt type, and data sources |
| 2. Hypothesis or Trigger | What started the hunt and how it would be confirmed or refuted |
| 3. Methodology | Frameworks, tools, hunt steps, and every query used |
| 4. Key Findings | What was found, why it matters, and what should happen next |
| 5. Detailed Analysis | Evidence, screenshots, attack timeline, and how the findings connect |
| 6. Indicators of Compromise | Network, account, file, and behavioral IOCs |
| 7. Intelligence Gaps | Where visibility was missing and how to close it |
| 8. ATT&CK Mapping | Each finding mapped to MITRE ATT&CK tactics and techniques |
| 9. Recommendations | Immediate, short-term, and long-term actions |
| 10. Appendix & References | Supporting material, glossary, and external sources |
| 11. Sensitivity Label | Data classification for the report |

The blank template is in [Template/README.md](./Template/README.md).

---

## Tools Used

- Microsoft Sentinel
- Kusto Query Language (KQL)
- MITRE ATT&CK

---

## Skills Demonstrated

- Hypothesis-driven threat hunting
- Writing KQL queries to search and filter log data
- Correlating activity across multiple log sources
- Building attack timelines from log evidence
- Mapping findings to MITRE ATT&CK
- Writing clear reports for technical and non-technical readers

---

## Disclaimer

All hunts in this repository were completed in a cyber range lab environment. Email addresses, IP addresses, domains, and organizations in these reports represent simulated infrastructure and fictional companies. Indicators of compromise are defanged and are shared for educational purposes only.
