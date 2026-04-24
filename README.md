# Detection Query Library

Open-source threat hunting and detection queries mapped to MITRE ATT&CK, written for Microsoft Sentinel (KQL) and IBM QRadar (AQL). Built and maintained by Charudatta Padhye as a companion to the [ML-Powered Encrypted Traffic Fingerprinting System](https://github.com/Git805/ML-Powered-Encrypted-Traffic-Fingerprinting-System).

---

## Query Index

### KQL — Microsoft Sentinel

| Query | Technique | Tactic | Severity | Log Source |
|---|---|---|---|---|
| [lateral_movement_smb_admin_shares.kql](kql/lateral_movement_smb_admin_shares.kql) | T1021.002 | Lateral Movement | Medium/High | NetworkFileShareEvents |
| [credential_dumping_lsass_access.kql](kql/credential_dumping_lsass_access.kql) | T1003.001 | Credential Access | High | SecurityEvent |
| [c2_beaconing_periodic_https.kql](kql/c2_beaconing_periodic_https.kql) | T1071.001 | Command & Control | Medium/High | CommonSecurityLog |
| [persistence_registry_run_keys.kql](kql/persistence_registry_run_keys.kql) | T1547.001 | Persistence | Low/Medium/High | DeviceRegistryEvents |
| [defence_evasion_lolbins.kql](kql/defence_evasion_lolbins.kql) | T1218 | Defence Evasion | Low/Medium/High | DeviceProcessEvents |

### AQL — IBM QRadar

| Query | Technique | Tactic | Severity | Log Source |
|---|---|---|---|---|
| [lateral_movement_smb_admin_shares.aql](aql/lateral_movement_smb_admin_shares.aql) | T1021.002 | Lateral Movement | Medium/High | Windows Security Events |
| [credential_dumping_lsass_access.aql](aql/credential_dumping_lsass_access.aql) | T1003.001 | Credential Access | High | Windows Security Events |
| [c2_beaconing_periodic_https.aql](aql/c2_beaconing_periodic_https.aql) | T1071.001 | Command & Control | Medium/High | Network Flow Logs |
| [persistence_scheduled_task.aql](aql/persistence_scheduled_task.aql) | T1053.005 | Persistence | Medium/High | Windows Security Events |
| [defence_evasion_lolbins.aql](aql/defence_evasion_lolbins.aql) | T1218 | Defence Evasion | Medium/High/Critical | Windows Security Events |

---

## MITRE ATT&CK Coverage

```
Lateral Movement (TA0008)
└── T1021.002  Remote Services: SMB/Windows Admin Shares

Credential Access (TA0006)
└── T1003.001  OS Credential Dumping: LSASS Memory

Command and Control (TA0011)
└── T1071.001  Application Layer Protocol: Web Protocols

Persistence (TA0003)
├── T1547.001  Boot or Logon Autostart: Registry Run Keys    [KQL only]
└── T1053.005  Scheduled Task/Job: Scheduled Task            [AQL only]

Defence Evasion (TA0005)
└── T1218     System Binary Proxy Execution (LOLBins)
```

---

## Usage

### Microsoft Sentinel (KQL)

1. Open Microsoft Sentinel → Logs
2. Copy and paste the query content
3. Adjust time range and exclusion lists for your environment
4. Save as a Scheduled Analytics Rule with appropriate alert threshold

```kql
// Example: Run lateral movement query and alert on results
// Set Schedule: Every 10 minutes
// Alert threshold: Results > 0
```

### IBM QRadar (AQL)

1. Open QRadar → Log Activity → Add Filter → Advanced Search
2. Paste the AQL query
3. Click Search
4. Save as a Saved Search for recurring execution
5. Create an Offense Rule triggered by the saved search results

```sql
-- All AQL queries use NOW() for time windowing
-- Adjust the interval (e.g., NOW() - 10 MINUTES) as needed
```

---

## Prerequisites

### KQL Queries Require

| Query | Required Table | Audit Setting |
|---|---|---|
| lateral_movement_smb | NetworkFileShareEvents | File Share Auditing enabled |
| credential_dumping_lsass | SecurityEvent | Audit Object Access (Success+Failure) |
| c2_beaconing | CommonSecurityLog | Firewall/proxy forwarding to Sentinel |
| persistence_registry | DeviceRegistryEvents | MDE onboarded endpoints |
| defence_evasion_lolbins | DeviceProcessEvents | MDE onboarded endpoints |

### AQL Queries Require

| Query | Required Log Source | Event IDs |
|---|---|---|
| lateral_movement_smb | Windows Security Event Log | 5140 |
| credential_dumping_lsass | Windows Security Event Log | 4656, 4663 |
| c2_beaconing | Network Flow Logs | Flow data |
| persistence_scheduled_task | Windows Security Event Log | 4698, 4702 |
| defence_evasion_lolbins | Windows Security Event Log | 4688 |

---

## Tuning Guide

Every query ships with exclusion lists that need environment-specific tuning. Before deploying to production:

**Step 1 — Run in monitor-only mode first**
Run each query manually for 1 week. Review all results. Identify legitimate activity generating false positives.

**Step 2 — Build your exclusion list**
Add legitimate hosts, processes, and accounts to the exclusion filters in each query. Common additions:
- SCCM / software deployment servers → lateral movement exclusions
- EDR agent processes → LSASS access exclusions
- Known monitoring tool IPs → beaconing exclusions
- Software installation accounts → LOLBin exclusions

**Step 3 — Adjust thresholds**
Each query documents its threshold logic. Start conservative (higher threshold = fewer alerts) and tune down as you validate.

**Step 4 — Stack queries for higher confidence**
Single query alerts → investigate. Multiple queries firing on same host within 1 hour → escalate immediately.

| Combination | Confidence | Recommended Action |
|---|---|---|
| C2 beaconing only | Medium | Investigate |
| C2 beaconing + LOLBin execution | High | Alert SOC |
| Lateral movement + credential dumping | High | Isolate host |
| All five queries on same host in 1 hour | Critical | Page on-call, isolate immediately |

---

## Companion Resources

- **ML-Based Detection:** [Encrypted Traffic Fingerprinting System](https://github.com/Git805/ML-Powered-Encrypted-Traffic-Fingerprinting-System) — achieves 94.7% precision on C2 beaconing in encrypted HTTPS traffic
- **Sigma Rules:** [detection-rules library](../rules/) — platform-agnostic Sigma rules for the same threat techniques
- **Blog:** [How I Built an ML System for Encrypted Threat Detection](https://dev.to/charudatta)

---

## Roadmap

- [ ] Splunk SPL versions of all queries
- [ ] Elastic EQL versions
- [ ] Darktrace model breach queries
- [ ] Cloud-native queries (AWS CloudTrail, GCP Audit Logs)
- [ ] Ransomware pre-cursor detection query pack
- [ ] BFSI sector-specific query pack

---

## Contributing

Found a false positive pattern? Have a tuning suggestion? Open an issue with:
- Your SIEM platform and version
- The query that generated the FP
- The legitimate process/activity causing it

Pull requests for new queries welcome — follow the existing comment structure including MITRE mapping, log source requirements, and tuning guidance.

---

## Author

**Charudatta Padhye**

NDR Solutions Engineer | Detection Engineering | ML for Security

[LinkedIn](https://linkedin.com/in/charudatta-padhye) · [GitHub](https://github.com/Git805) · [Blog](https://dev.to/charudatta)

---

*If this library helped your threat hunting, a GitHub star helps other practitioners find it.*
