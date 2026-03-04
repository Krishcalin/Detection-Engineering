# Detection-Engineering

Security Operation Center (SOC) attack detection and response rules for Splunk SIEM. Each rule includes comprehensive SPL queries, MITRE ATT&CK mapping, false positive tuning guidance, investigation queries, and incident response playbooks.

## Repository Structure

```
Detection-Engineering/
├── README.md
└── splunk_rules/
    └── credential_access/
        ├── adcs_attack_detection.yml
        ├── dcsync_attack_detection.yml
        └── kerberoasting_attack_detection.yml
```

## Detection Rules

| Rule File | Attack Technique | MITRE ID | Severity | Detection Vectors |
|-----------|-----------------|----------|----------|-------------------|
| `adcs_attack_detection.yml` | ADCS Certificate Abuse (ESC1-ESC13) | T1649 | CRITICAL | 9 rules + 5 investigation queries |
| `dcsync_attack_detection.yml` | DCSync Credential Dumping | T1003.006 | CRITICAL | 5 rules + 4 investigation queries |
| `kerberoasting_attack_detection.yml` | Kerberoasting + AS-REP Roasting | T1558.003, T1558.004 | CRITICAL | 7 rules + 5 investigation queries |

## Rule Format

Each detection rule file (YAML) includes:

- **Rule metadata** — name, description, MITRE ATT&CK mapping, confidence, risk score
- **Splunk SPL query** — ready-to-deploy correlation search
- **Schedule configuration** — cron, time window, throttle settings
- **Splunk ES actions** — notable event creation, risk scoring
- **False positive guidance** — known FPs and tuning instructions
- **Investigation queries** — manual IR queries for deeper analysis
- **Response playbook** — step-by-step incident response procedure

## DCSync Attack Detection

**File**: `splunk_rules/credential_access/dcsync_attack_detection.yml`

Detects DCSync credential dumping (MITRE T1003.006) through 5 complementary detection rules:

| Rule | Detection Method | Event IDs | Confidence |
|------|-----------------|-----------|------------|
| Rule 1 | User account performing replication | 4662 + 4624 | HIGH |
| Rule 2 | Replication from non-DC source IP | 4662 + 4624 + DC lookup | HIGH |
| Rule 3 | Replication permissions granted | 5136 | HIGH |
| Rule 4 | Bulk replication burst (volume anomaly) | 4662 | MEDIUM-HIGH |
| Rule 5 | DRSUAPI network traffic from non-DC | Network Traffic model | HIGH |

### Prerequisites

1. **Audit Policy** — Enable "Audit Directory Service Access" (Success) on all DCs
2. **SACL** — Configure auditing on domain root for replication extended rights
3. **Log Forwarding** — Splunk Universal Forwarder on all DCs forwarding Security logs
4. **DC IP Lookup** — `dc_ip_list.csv` for Rules 2 and 5

### Quick Deploy

1. Copy the SPL query from Rule 1 into Splunk > Search & Reporting
2. Replace `YOURDC01$`, `YOURDC02$` with your actual DC machine account names
3. Add any Azure AD Connect service accounts (`MSOL_*`) to the exclusion list
4. Save as a scheduled search or Splunk ES correlation search
5. Test with a 24-hour lookback to verify baseline before enabling alerts

## ADCS Attack Detection

**File**: `splunk_rules/credential_access/adcs_attack_detection.yml`

Detects Active Directory Certificate Services abuse (MITRE T1649) through 9 complementary detection rules covering ESC1 through ESC13:

| Rule | Detection Method | Event IDs | ESC Variant | Confidence |
|------|-----------------|-----------|-------------|------------|
| Rule 1 | Certificate issued with SAN mismatch | 4887 | ESC1 | HIGH |
| Rule 2 | Suspicious PKINIT certificate authentication | 4768 | ESC1/ESC3 | HIGH |
| Rule 3 | Certificate template modification | 5136 | ESC4 | HIGH |
| Rule 4 | EDITF_ATTRIBUTESUBJECTALTNAME2 flag | 4688, 4104, 4657 | ESC6 | CRITICAL |
| Rule 5 | Machine PKINIT from unexpected IP | 4768 | ESC8 | HIGH |
| Rule 6 | Vulnerable template detection (daily audit) | 4898 | ESC2/ESC3 | MEDIUM |
| Rule 7 | ADCS attack tool detection | 4688, 4104 | All | HIGH |
| Rule 8 | OID group link modification | 5136 | ESC13 | HIGH |
| Rule 9 | CA configuration change | 4890, 4876 | ESC5/ESC7 | MEDIUM-HIGH |

### Prerequisites

1. **Audit Policy** — Enable "Audit Certification Services" (Success + Failure) on all CAs
2. **Audit Policy** — Enable "Audit Directory Service Changes" (Success) on all DCs
3. **Log Forwarding** — Splunk Universal Forwarder on all CAs and DCs forwarding Security logs
4. **Machine IP Lookup** — `machine_ip_list.csv` for Rule 5 (machine account to expected IP mapping)
5. **Certificate Template Auditing** — Enable object access auditing on certificate template objects in AD

### Quick Deploy

1. Copy the SPL query from Rule 1 into Splunk > Search & Reporting
2. Replace `YOUR-CA-01` with your actual CA server hostname
3. Add legitimate enrollment service accounts to the exclusion list
4. Save as a scheduled search or Splunk ES correlation search
5. Test with a 7-day lookback to establish a baseline of normal certificate issuance
6. Deploy Rules 6 and 9 first (lower noise) before enabling the higher-fidelity rules

## Kerberoasting Attack Detection

**File**: `splunk_rules/credential_access/kerberoasting_attack_detection.yml`

Detects Kerberoasting (MITRE T1558.003) and AS-REP Roasting (MITRE T1558.004) through 7 complementary detection rules:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | RC4 encryption downgrade in TGS request | 4769 | T1558.003 | HIGH |
| Rule 2 | Bulk TGS requests — volume anomaly (spray) | 4769 | T1558.003 | HIGH |
| Rule 3 | Privileged service account targeted (adminCount=1) | 4769 | T1558.003 | HIGH |
| Rule 4 | AS-REP Roasting — pre-auth disabled account | 4768 | T1558.004 | HIGH |
| Rule 5 | Kerberoasting tool execution (Rubeus, Invoke-Kerberoast, Impacket) | 4688, 4104 | T1558.003/004 | HIGH |
| Rule 6 | RC4 TGS from external or non-standard source | 4769 | T1558.003 | HIGH |
| Rule 7 | SPN enumeration precursor — LDAP/PowerShell | 1644, 4688, 4104 | T1087.002 | MEDIUM |

### Prerequisites

1. **Audit Policy** — Enable "Audit Kerberos Service Ticket Operations" (Success + Failure) on all DCs
2. **Audit Policy** — Enable "Audit Kerberos Authentication Service" (Success + Failure) on all DCs
3. **Command-Line Logging** — Enable process creation with command-line logging via GPO on all endpoints
4. **PowerShell Logging** — Enable Script Block Logging via GPO on all endpoints
5. **Log Forwarding** — Splunk Universal Forwarder on all DCs and endpoints forwarding Security + PowerShell logs
6. **Privileged SPN Lookup** — `privileged_spn_accounts.csv` in Splunk for Rule 3 (scheduled AD export)

### Quick Deploy

1. Start with Rule 1 (RC4 downgrade) — highest-confidence, lowest noise in AES-enforced environments
2. Baseline your environment for legitimate RC4 consumers before enabling (run as report for 14 days first)
3. Build the `privileged_spn_accounts.csv` lookup from AD (`adminCount=1` + `servicePrincipalName` set)
4. Deploy Rule 4 (AS-REP Roasting) immediately — `PreAuthType=0` should never occur in hardened AD
5. Deploy Rule 5 (tool detection) immediately — zero expected false positives from legitimate tooling
6. Tune Rule 2 volume threshold (default 10 SPNs/15 min) using your environment baseline

## Requirements

- Splunk Enterprise 8.x+ or Splunk Cloud
- Splunk Enterprise Security (ES) recommended for notable events and risk framework
- Windows Security Event Logs from Domain Controllers (sourcetype: `XmlWinEventLog:Security`)
- PowerShell 5.1+ on DCs for audit policy configuration
