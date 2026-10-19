# Sigma Detection Lab: Detecting Windows Security Log Clearing (Event ID 1102)

A hands-on walkthrough of **detection-as-code** with [Sigma](https://github.com/SigmaHQ/sigma). I write one detection rule in YAML, then convert it into a Splunk query with `sigma-cli`. Every step includes the **why**, not just the command.

- **Author:** Uncle_Dedayo
- **Date:** 2026-10-19
- **Rule status:** experimental (not yet validated against live logs)

---

## 1. What is Sigma and why detection-as-code?

Sigma is an open, vendor-neutral format for writing detection rules for **log-based** threats. Every SIEM has its own query language (Splunk uses SPL, Microsoft Sentinel uses KQL, Elastic uses Lucene/EQL), so without Sigma the same detection must be rewritten for each platform.

With Sigma, you write the detection **once** in readable YAML and a converter translates it into the SIEM's own language. Because the rule is just a text file, it can be stored in Git, reviewed, versioned, and shared like any other code. That is what "detection-as-code" means.

Sigma is to log detections what YARA is to files and Snort is to network traffic.

**Important scope notes**

- Sigma **defines** what to detect. It does not trigger anything. The SIEM (or your automation) handles alerting and response. A good comparison is AWS EventBridge: EventBridge matches events and triggers actions, while Sigma only describes the match.
- Sigma works on logs only, and complex multi-event correlation depends on what the target SIEM supports.
- You still write each rule yourself, but only once, instead of once per SIEM.

---

## 2. How Sigma adds value to a SOC and detection pipeline

1. **Cross-platform detection sharing:** one rule works on any supported SIEM, so teams and the community can share detections regardless of which tools they run.
2. **Centralized detection repository:** all rules live in one Git repository, versioned, peer-reviewed, and auditable.
3. **Automated conversion:** `sigma convert` replaces hand-writing and hand-translating queries, which reduces mistakes and saves time.
4. **Deployment:** converted queries can be pushed into the SIEM as scheduled searches or alerts, ideally through a CI/CD pipeline.

---

## 3. Setup

### Step 1: Create the project folder

```bash
mkdir sigma-detection-lab
cd sigma-detection-lab
git init
```

**Why:** a dedicated, version-controlled folder keeps the rule and documentation together and ready to publish.

### Step 2: Install Sigma CLI

```bash
pip install sigma-cli
sigma version
```

**Why:** `sigma-cli` (built on the pySigma library) is the current tool for listing, validating, and converting rules. It replaces the older `sigmac` script, which is retired. It is lightweight: it runs only when called, with no background service.

My installed version: `3.1.0` (matched the latest on PyPI).

### Step 3: Install the Splunk backend plugin

```bash
sigma plugin install splunk
sigma list targets
```

**Why:** the CLI alone only understands Sigma YAML. A **backend plugin** teaches it how to translate into a specific SIEM's query language. No plugin means nothing to convert *to*.

`sigma plugin list` printed nothing for me, because it queries the online plugin catalog and is not a reliable check of what is installed. `sigma list targets` is the reliable check, and it showed:

| Identifier | Target query language | Pipeline required |
|---|---|---|
| `splunk` | Splunk SPL and tstats data model queries | Yes |
| `splunk_spl2` | Splunk SPL2 queries | Yes |

"Pipeline required: Yes" means Sigma's generic field names must be mapped to Splunk's real field names at conversion time (see Step 6).

> Splunk itself is **not** needed for this lab. `sigma convert` only produces query text. A real Splunk instance is only needed to run the query against live logs.

---

## 4. Writing the rule

### What we are detecting

**Windows Event ID 1102** is written to the Security log when the Security event log is cleared. Attackers often clear logs to erase evidence of their activity, so this event is a strong signal.

### The three parts of a Sigma rule

| Section | Purpose |
|---|---|
| **Metadata** | Describes the rule: title, author, severity, MITRE tags |
| **Logsource** | Says which logs to search |
| **Detection** | The matching logic |

### Final rule: `log_cleared.yml`

```yaml
title: Windows Security Event Log Cleared
id: 775fd40d-b213-40ce-8c7d-b32f65b25233
status: experimental
description: Detects when the Windows Security event log is cleared (Event ID 1102), which attackers often do to erase evidence of their activity
author: Uncle_Dedayo
date: 2026-10-19
tags:
  - attack.defense_evasion
  - attack.t1070.001
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 1102
  condition: selection
falsepositives:
  - Legitimate log clearing by an administrator during maintenance
level: high
```

### Why each field

- **`title`**: a short, clear name saying exactly what happened.
- **`id`**: a unique UUID so the rule can be tracked and referenced. Generated with:
  ```bash
  python -c "import uuid; print(uuid.uuid4())"
  ```
- **`status: experimental`**: an honest maturity label. The rule has not yet been tested against real Windows logs. `experimental` is a standard label (the official SigmaHQ repository uses it for new rules). Move it to `test` after the rule catches a real log clear in a lab (clear the log yourself and confirm it fires), and to `stable` after it has run against normal activity with few or no false alarms.
- **`description`**: one sentence on what the rule detects and why it matters.
- **`author` and `date`**: credit and tracking.
- **`tags`** (optional, but recommended): they map the rule to MITRE ATT&CK so analysts and SIEMs can categorize it.
  - `attack.defense_evasion` is the **tactic**: the attacker's goal (hiding).
  - `attack.t1070.001` is the **technique**: T1070 is *Indicator Removal*, and `.001` is the sub-technique *Clear Windows Event Logs*, which is exactly what Event ID 1102 records.
  - In YAML, each list item needs a space after the hyphen (`- attack.defense_evasion`). Without it, the line is read as plain text, not a list.
- **`logsource`**: `product: windows` and `service: security` point at the exact log where Event 1102 is recorded. `category` is not needed here, because it is used for generic event types such as `process_creation`.
- **`detection`**:
  - `selection` is a **naming convention**, not a requirement. Any name works as long as `condition` uses the same name.
  - Field names are case-sensitive, so it must be `EventID`, not `Eventid`.
  - `condition: selection` tells Sigma to alert when that block matches. An empty condition is invalid.
- **`falsepositives`**: administrators do sometimes clear logs (full disk, decommissioning, reimaging), so this is a possible benign cause. Best practice is to archive or forward logs rather than wipe them, so any clear should still be checked against a change ticket.
- **`level: high`**: clearing the Security log is rarely innocent. By SigmaHQ convention, `level` sits at the bottom of the file (YAML does not enforce order).

---

## 5. Validating and converting

### Step 4: Validate the rule

```bash
sigma check log_cleared.yml
```

**Why:** validation catches structural mistakes before conversion. Run it from inside the folder that holds the file, or give the full path.

**Troubleshooting:** in my run, parsing completed but the check stage failed with a network error (a `urllib` / `socket` traceback). The check tries to download MITRE ATT&CK data to verify tags, and my connection could not reach it. That error says nothing about the rule itself. Retry with a working connection if you want the full validation.

### Step 5: List the available pipelines

```bash
sigma list pipelines
```

**Why:** a **processing pipeline** is a set of translation rules that maps Sigma's generic names to the SIEM's real ones. The list showed:

| Identifier | Priority | Purpose |
|---|---|---|
| `splunk_windows` | 20 | Splunk Windows log source conditions |
| `splunk_sysmon_acceleration` | 25 | Splunk Windows Sysmon search acceleration keywords |
| `splunk_cim` | 20 | Splunk CIM data model mapping |

`splunk_windows` is the right one for this rule. The other two are for Sysmon logs and Splunk's CIM data model, which this lab does not use.

### Step 6: Convert the rule to Splunk SPL

```bash
sigma convert -t splunk -p splunk_windows log_cleared.yml
```

- `-t splunk` is the target SIEM.
- `-p splunk_windows` is the pipeline from Step 5.

**Output:**

```spl
source="WinEventLog:Security" EventCode=1102
```

How the rule became this query:

- `source="WinEventLog:Security"` comes from our `logsource` block.
- `EventCode=1102` is our `EventID` field, renamed by the pipeline to Splunk's real field name.

One YAML rule became a real SPL query.

---

## 6. Turning the query into a Splunk alert

The converted SPL can be used in Splunk in two ways:

1. **As a hunt:** paste it into the Splunk search bar and run it to check historical logs for the same behavior.
2. **As an alert:** paste it into the search bar, choose **Save As > Alert**, set a schedule (or real-time), and set the trigger condition to **number of results is greater than 0**.

**Requirements and notes**

- The alert only fires if Windows Security logs are already being sent into Splunk, usually through a **Universal Forwarder**.
- `index=<name>` is **not always required**. Without it, Splunk searches your role's default indexes, so the query works if the Windows logs land in one of those. If the logs go to a custom index outside your defaults, add `index=<name>` or the search returns nothing.
- To find which index your Security events landed in, run:
  ```spl
  source="WinEventLog:Security" | stats count by index
  ```
- The forwarder's `inputs.conf` controls the destination with an `index =` line under `[WinEventLog://Security]`. If the line is missing, events go to `main`. The index must already exist in Splunk, otherwise the events are dropped.
- An **index** is a storage bucket in Splunk, like a labeled folder for data. Indexes are usually split by access needs, retention, and volume, not one per log type.

**The key split:** Sigma defines the detection. Splunk's alert does the triggering.

### Hunting vs investigating

A converted Sigma rule is ideal for repeatable questions such as "has anyone cleared the Security log?". When an alert fires and you need to dig into one case (for example, "what else did this user do on this machine today?"), you write a custom SPL query around that user, host, and time window. Sigma is built for reusable detections, not one-off investigation.

> This section describes how to use the query in Splunk. I have not yet run it against a live Splunk instance in this lab.

---

## 7. Sigma is not only for Windows: cloud services too

Sigma rules can target cloud logs as well as endpoint logs. For AWS, the `logsource` points at CloudTrail, and the detection matches API call fields such as `eventSource` and `eventName`, much like an EventBridge event pattern does.

**How this compares to EventBridge**

| | EventBridge | Sigma |
|---|---|---|
| Where it runs | Inside AWS, as events happen | In your SIEM, over CloudTrail logs already ingested |
| Portability | AWS only | Same rule converts to many SIEMs |
| Triggers actions | Yes (targets such as Lambda or SNS) | No, it only defines the detection |

The same approach applies to other cloud and identity sources (Azure, GCP, Okta, and others), as long as their logs are collected in the SIEM. For AWS, CloudTrail must be forwarded into the SIEM first, otherwise there is nothing for the converted query to search.

---

## 8. Next steps

- **Test the rule** by clearing the Security log in a lab VM (`wevtutil cl Security`) and confirming Event ID 1102 appears, then raise `status` to `test`.
- **Run it in Splunk** against forwarded logs and save it as an alert.
- **Extend to other SIEMs.** The same rule can be converted for other platforms by installing the matching backend plugin, for example Elasticsearch:
  ```bash
  sigma plugin install elasticsearch
  sigma convert -t elasticsearch log_cleared.yml
  ```
  *(Not yet run in this lab. Verify the exact target name and any required pipeline with `sigma list targets` and `sigma list pipelines` before publishing results.)*

---

## 9. Repository layout

```
sigma-detection-lab/
├── README.md
└── log_cleared.yml
```

## References

- Sigma project: https://github.com/SigmaHQ/sigma
- Book: *Practical Detection Engineering with Sigma*
- MITRE ATT&CK T1070.001, Indicator Removal: Clear Windows Event Logs
