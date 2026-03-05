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
        ├── golden_ticket_attack_detection.yml
        ├── gpo_modification_detection.yml
        ├── kerberoasting_attack_detection.yml
        ├── lsass_credential_dumping_detection.yml
        ├── ntds_dit_extraction_detection.yml
        ├── pass_the_hash_detection.yml
        ├── password_spraying_detection.yml
        └── privileged_group_membership_modification_detection.yml
```

## Detection Rules

| Rule File | Attack Technique | MITRE ID | Severity | Detection Vectors |
|-----------|-----------------|----------|----------|-------------------|
| `adcs_attack_detection.yml` | ADCS Certificate Abuse (ESC1-ESC13) | T1649 | CRITICAL | 9 rules + 5 investigation queries |
| `dcsync_attack_detection.yml` | DCSync Credential Dumping | T1003.006 | CRITICAL | 5 rules + 4 investigation queries |
| `golden_ticket_attack_detection.yml` | Golden Ticket Kerberos Forgery | T1558.001 | CRITICAL | 6 rules + 8 investigation queries |
| `gpo_modification_detection.yml` | GPO Modification / Domain Policy Abuse | T1484.001 | CRITICAL | 7 rules + 8 investigation queries |
| `kerberoasting_attack_detection.yml` | Kerberoasting + AS-REP Roasting | T1558.003, T1558.004 | CRITICAL | 7 rules + 5 investigation queries |
| `lsass_credential_dumping_detection.yml` | LSASS Memory Credential Dumping | T1003.001 | CRITICAL | 7 rules + 5 investigation queries |
| `ntds_dit_extraction_detection.yml` | NTDS.dit Database Extraction | T1003.003 | CRITICAL | 8 rules + 8 investigation queries |
| `pass_the_hash_detection.yml` | Pass-the-Hash Lateral Movement | T1550.002 | CRITICAL | 6 rules + 5 investigation queries |
| `password_spraying_detection.yml` | Password Spraying + Brute Force | T1110.003, T1110.001 | HIGH–CRITICAL | 7 rules + 4 investigation queries |
| `privileged_group_membership_modification_detection.yml` | Privileged AD Group Modification | T1098.001 | CRITICAL | 6 rules + 7 investigation queries |

## Rule Format

Each detection rule file (YAML) includes:

- **Rule metadata** — name, description, MITRE ATT&CK mapping, confidence, risk score
- **Splunk SPL query** — ready-to-deploy correlation search
- **Schedule configuration** — cron, time window, throttle settings
- **Splunk ES actions** — notable event creation, risk scoring
- **False positive guidance** — known FPs and tuning instructions
- **Investigation queries** — manual IR queries for deeper analysis
- **Response playbook** — step-by-step incident response procedure

---

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

---

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

---

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

---

## LSASS Credential Dumping Detection

**File**: `splunk_rules/credential_access/lsass_credential_dumping_detection.yml`

Detects OS credential dumping via LSASS process memory (MITRE T1003.001) through 7 complementary detection rules covering Mimikatz, Sysinternals ProcDump, comsvcs.dll MiniDump (LOLBAS), Task Manager dumps, WerFault abuse, and SSP/DLL injection:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | Sysmon ProcessAccess to lsass.exe — suspicious GrantedAccess bitmask | Sysmon 10 | T1003.001 | HIGH |
| Rule 2 | LSASS memory dump file created in suspicious path | Sysmon 11 | T1003.001 | HIGH |
| Rule 3 | Mimikatz binary, CLI syntax, or Invoke-Mimikatz detected | 4688, Sysmon 1, 4104 | T1003.001 | HIGH |
| Rule 4 | ProcDump / comsvcs.dll MiniDump / createdump / WerFault targeting LSASS | 4688, Sysmon 1 | T1003.001, T1218.011 | HIGH |
| Rule 5 | Unsigned or unexpected DLL loaded into lsass.exe process space | Sysmon 7 | T1003.001, T1547.005 | MEDIUM-HIGH |
| Rule 6 | WDigest UseLogonCredential registry key enabled — plaintext credential staging | Sysmon 13, 4657 | T1003.001, T1112 | HIGH |
| Rule 7 | SeDebugPrivilege acquired by non-system process — Mimikatz precursor | 4703 | T1134.001 | MEDIUM |

### Prerequisites

1. **Sysmon Deployment** — Deploy Sysmon with LSASS ProcessAccess (Event 10), FileCreate for .dmp (Event 11), ImageLoad into lsass.exe (Event 7), and RegistryValueSet (Event 13) rules enabled
2. **Audit Policy** — Enable "Audit Process Creation" (Success) with command-line logging on all endpoints
3. **PowerShell Logging** — Enable Script Block Logging via GPO on all endpoints
4. **Audit Token Rights** — Enable "Audit Token Right Adjusted" (Event 4703) for Rule 7
5. **Log Forwarding** — Splunk Universal Forwarder on all endpoints forwarding Security + Sysmon + PowerShell logs
6. **LSASS Allowlist** — Build `lsass_access_allowlist.csv` with known-legitimate processes (EDR/AV agents, Windows system processes)

### Quick Deploy

1. Deploy Rule 3 (Mimikatz CLI syntax) and Rule 4 (ProcDump/comsvcs.dll) first — zero noise, immediate value
2. Deploy Rule 6 (WDigest enable) immediately — no false positives, and gives advance warning before dumping occurs
3. Deploy Rule 2 (dump file creation) next — low noise, catches the output artifact regardless of tool used
4. Build your `lsass_access_allowlist.csv` by monitoring Rule 1 (Sysmon Event 10) in report mode for 7 days to identify legitimate LSASS callers in your environment
5. Enable Rule 1 (GrantedAccess) after allowlist is built — highest fidelity, requires tuning
6. Enable LSASS PPL (`RunAsPPL=1`) and Credential Guard to reduce attack surface while detection is being tuned

---

## Pass-the-Hash Detection

**File**: `splunk_rules/credential_access/pass_the_hash_detection.yml`

Detects Pass-the-Hash lateral movement (MITRE T1550.002) through 6 complementary detection rules covering classic NTLM hash replay, Mimikatz sekurlsa::pth, Overpass-the-Hash, Impacket tool signatures, and chained TTP correlation with LSASS dumps:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | Classic PtH — NTLM Type 3, null subject SID, KeyLength=0 | 4624 | T1550.002 | HIGH |
| Rule 2 | Mimikatz sekurlsa::pth — LogonType 9 + seclogo process | 4624 | T1550.002 | HIGH |
| Rule 3 | Rapid NTLM lateral movement — single source, 5+ targets in 5 min | 4624 | T1021.002 | HIGH |
| Rule 4 | Impacket tool signatures (psexec/smbexec/wmiexec hardcoded strings) | 7045, 4697, 5140 | T1550.002 | HIGH |
| Rule 5 | Overpass-the-Hash — RC4 TGT request via NT hash conversion | 4768 | T1550.002 | MEDIUM-HIGH |
| Rule 6 | Chained TTP — LSASS access then NTLM logon from same source | Sysmon 10 + 4624 | T1003.001 + T1550.002 | HIGH |

### Prerequisites

1. **Audit Policy** — Enable "Audit Logon" (Success + Failure) on all domain-joined hosts
2. **Audit Policy** — Enable "Audit Special Logon" (Success) on all hosts
3. **Audit Policy** — Enable "Audit Kerberos Authentication Service" (Success + Failure) on all DCs
4. **Log Forwarding** — Splunk Universal Forwarder on all hosts forwarding Security logs
5. **Sysmon** — Deploy Sysmon with ProcessAccess (Event 10) for LSASS — required for Rule 6
6. **Lookup Tables** — `dc_ip_list.csv` (DC IPs) + `legacy_ntlm_hosts.csv` (legitimate NTLM consumers)

### Quick Deploy

1. Deploy Rule 2 (Mimikatz LogonType 9 / seclogo) immediately — zero expected false positives
2. Deploy Rule 4 (Impacket signatures) immediately — hardcoded tool strings have near-zero FP rate
3. Deploy Rule 1 (classic PtH) after building `legacy_ntlm_hosts.csv` to suppress legitimate NTLM sources
4. Enable Rule 3 (rapid lateral movement) after confirming the 5-target threshold fits your environment
5. Tune Rule 5 (Overpass-the-Hash) only after enforcing AES encryption domain-wide (disabling RC4)
6. Enable Rule 6 (chained TTP) after Sysmon LSASS ProcessAccess monitoring is in place

---

## Password Spraying Detection

**File**: `splunk_rules/credential_access/password_spraying_detection.yml`

Detects Password Spraying (MITRE T1110.003) and Brute Force (T1110.001) attacks through 7 complementary detection rules covering Kerberos and NTLM spray, account lockout storms, spray hit confirmation, username enumeration, and slow low-cadence APT spray patterns:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | Kerberos spray — 4771 Status=0x18, ≥10 accounts in 5 min | 4771 | T1110.003 | HIGH |
| Rule 2 | NTLM spray at DC — 4776 Status=0xC000006A, ≥10 accounts in 5 min | 4776 | T1110.003 | HIGH |
| Rule 3 | Single-account brute force — 4625, ≥20 failures, dc(account)≤2 | 4625 | T1110.001 | HIGH |
| Rule 4 | Account lockout storm — ≥5 locked accounts in 10 min | 4740 | T1110.003 | MEDIUM-HIGH |
| Rule 5 | Spray hit — failures ≥10 + success from same IP within 30 min | 4625 + 4624 | T1110.003 | HIGH |
| Rule 6 | Kerberos username enumeration — 4768 Status=0x6, ≥10 accounts in 2 min | 4768 | T1087.002 | HIGH |
| Rule 7 | Slow APT spray — 24h window, ≥20 accounts, <4 attempts/account | 4771, 4776 | T1110.003 | MEDIUM |

### Prerequisites

1. **Audit Policy** — Enable "Audit Kerberos Authentication Service" (Success + Failure) on all DCs
2. **Audit Policy** — Enable "Audit Credential Validation" (Success + Failure) on all DCs
3. **Audit Policy** — Enable "Audit Logon" (Success + Failure) on all DCs and endpoints
4. **Audit Policy** — Enable "Audit Account Lockout" (Success) on all DCs
5. **Log Forwarding** — Splunk Universal Forwarder on all DCs and endpoints forwarding Security logs

### Quick Deploy

1. Deploy Rule 5 (spray hit) first — confirms successful compromise, highest priority alert
2. Deploy Rule 1 (Kerberos 4771) immediately — Kerberos spray is the most common modern technique
3. Deploy Rule 4 (lockout storm) immediately — even lagging, mass lockouts need immediate response
4. Run Rule 7 (slow spray) in report mode for 30 days before alerting to baseline your environment
5. Tune the dc(account) threshold in Rule 1 (default: 10 accounts / 5 min) using 14-day baseline data

---

## Privileged Group Membership Modification Detection

**File**: `splunk_rules/credential_access/privileged_group_membership_modification_detection.yml`

Detects unauthorized modifications to privileged Active Directory groups (MITRE T1098.001) through 6 complementary detection rules covering all group types, direct LDAP writes, bulk escalation patterns, nested group abuse, and AdminSDHolder persistence:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | Member added to privileged group (all scope types) | 4728, 4732, 4756 | T1098.001 | HIGH |
| Rule 2 | Direct LDAP 'member' attribute write to privileged group | 5136 | T1098.001 | HIGH |
| Rule 3 | Bulk escalation — ≥3 privileged groups modified in 10 min | 4728, 4732, 4756 | T1098.001 | HIGH |
| Rule 4 | Nested group added to privileged group (inherited privilege) | 4728, 4732, 4756 | T1098.001 | MEDIUM-HIGH |
| Rule 5 | AdminSDHolder ACL modification — covert persistent privilege | 5136 | T1098.001 | HIGH |
| Rule 6 | Masquerade group creation mimicking privileged group name | 4731 | T1098.001 | MEDIUM |

### Prerequisites

1. **Audit Policy** — Enable "Audit Security Group Management" (Success) on all DCs
2. **Audit Policy** — Enable "Audit Directory Service Changes" (Success) on all DCs
3. **SACL** — Configure auditing on CN=AdminSDHolder for Rule 5
4. **Log Forwarding** — Splunk Universal Forwarder on all DCs forwarding Security logs
5. **Lookup Tables** — `privileged_group_admin_allowlist.csv` for known-legitimate GPO admin accounts

### Quick Deploy

1. Deploy Rule 1 immediately — direct group additions are the core detection with highest value
2. Deploy Rule 5 (AdminSDHolder) immediately — no false positives; very rare legitimate modification
3. Deploy Rule 2 (LDAP direct write) to catch BloodHound-based attacks that bypass standard events
4. Build the `privileged_group_admin_allowlist.csv` lookup to suppress IAM provisioning tool accounts
5. Enable Rule 3 (bulk escalation) after confirming the 3-group threshold does not fire during planned AD migrations

---

## Golden Ticket Detection

**File**: `splunk_rules/credential_access/golden_ticket_attack_detection.yml`

Detects Golden Ticket Kerberos forgery attacks (MITRE T1558.001) through 6 complementary detection rules. Golden Tickets are forged TGTs signed with the KRBTGT hash — no Event 4768 is generated by the KDC, making detection rely on secondary indicators:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | RC4 TGT in AES-enforced environment | 4768 | T1558.001 | HIGH |
| Rule 2 | RC4 TGS request in AES-enforced environment | 4769 | T1558.001 | MEDIUM-HIGH |
| Rule 3 | TGS request without preceding TGT issuance (forged TGT presented) | 4769 (absent 4768) | T1558.001 | HIGH |
| Rule 4 | Special privilege Kerberos logon with no TGT issuance | 4672 + 4624 (absent 4768) | T1558.001 | HIGH |
| Rule 5 | Anomalous krbtgt service ticket request | 4769 | T1558.001 | MEDIUM-HIGH |
| Rule 6 | TGT/TGS encryption type mismatch (AES TGT + RC4 TGS) | 4768 + 4769 | T1558.001 | MEDIUM |

### Prerequisites

1. **Audit Policy** — Enable "Audit Kerberos Authentication Service" (Success + Failure) on all DCs
2. **Audit Policy** — Enable "Audit Kerberos Service Ticket Operations" (Success + Failure) on all DCs
3. **Audit Policy** — Enable "Audit Special Logon" (Success) on all hosts
4. **AES Enforcement** — Domain-wide RC4 disablement via GPO required for Rule 1 and 2 to be effective
5. **Log Forwarding** — All DC Security logs in one Splunk index (critical for absence-of-TGT correlation)
6. **Lookup Tables** — `rc4_tgt_allowlist.csv` (legacy RC4 consumers) + `privileged_accounts.csv` (Rule 3 scope)

### Quick Deploy

1. Deploy Rule 3 (TGS without TGT) scoped to privileged accounts only — highest-fidelity indicator
2. Deploy Rule 4 (special privilege without TGT) — combination of 4672 + 4624 + absent 4768 is definitive
3. Enable Rules 1 and 2 (RC4 anomalies) ONLY after fully enforcing AES domain-wide and building allowlists
4. Run Rules 1 and 2 in report mode for 14 days first to eliminate legacy RC4 consumers from scope
5. For environments without AES enforcement: focus on Rules 3, 4, and 6 (encryption-agnostic indicators)

---

## NTDS.dit Extraction Detection

**File**: `splunk_rules/credential_access/ntds_dit_extraction_detection.yml`

Detects NTDS.dit Active Directory database extraction (MITRE T1003.003) through 8 complementary detection rules covering all major extraction techniques — ntdsutil IFM, VSS-based copies, LOLBin abuse, PowerShell WMI, and file-level SACL auditing:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | ntdsutil IFM execution on DC | 4688, Sysmon 1 | T1003.003 | HIGH |
| Rule 2 | vssadmin shadow copy creation on DC | 4688, Sysmon 1 | T1003.003 | HIGH |
| Rule 3 | diskshadow /s script mode on DC | 4688, Sysmon 1 | T1003.003 | HIGH |
| Rule 4 | esentutl /y /vss copy of NTDS.dit | 4688, Sysmon 1 | T1003.003 | HIGH |
| Rule 5 | PowerShell Win32_ShadowCopy + NTDS file copy | 4104 | T1003.003 | HIGH |
| Rule 6 | ntds.dit file created outside NTDS directory | Sysmon 11 | T1003.003 | HIGH |
| Rule 7 | NTDS.dit direct file access via SACL audit | 4663 | T1003.003 | MEDIUM-HIGH |
| Rule 8 | Multi-stage correlation — VSS creation + ntds.dit copy | Sysmon 1 + 11 | T1003.003 | HIGH |

### Prerequisites

1. **Process Creation Logging** — Enable "Audit Process Creation" (Success) with command-line on all DCs
2. **PowerShell Logging** — Enable Script Block Logging via GPO on all DCs
3. **Sysmon Deployment** — Deploy Sysmon on DCs with ProcessCreate (Event 1), FileCreate (Event 11)
4. **SACL on NTDS.dit** — Configure `Everyone: Read Data` auditing on `%SystemRoot%\NTDS\ntds.dit` for Rule 7
5. **Log Forwarding** — Splunk Universal Forwarder on all DCs forwarding Security + Sysmon + PowerShell logs
6. **DC Hostname Lookup** — `dc_hostnames.csv` to restrict vssadmin/diskshadow alerts to DCs only

### Quick Deploy

1. Deploy Rule 1 (ntdsutil IFM) immediately — highest fidelity, almost no legitimate use outside DCPromo
2. Deploy Rule 6 (ntds.dit outside NTDS path via Sysmon 11) — tool-agnostic, catches any extraction method
3. Deploy Rule 8 (kill chain correlation) for the highest-confidence, lowest-FP combined indicator
4. Deploy Rules 2–5 after populating `dc_hostnames.csv` to avoid false positives on non-DC servers
5. Configure SACL on NTDS.dit on all DCs to enable Rule 7 (file-level access audit)

---

## GPO Modification Detection

**File**: `splunk_rules/credential_access/gpo_modification_detection.yml`

Detects malicious Group Policy Object modification (MITRE T1484.001) through 7 complementary detection rules covering AD-layer GPO changes, SYSVOL payload injection, built-in policy tampering, security control disabling, and kill-chain correlation:

| Rule | Detection Method | Event IDs | Technique | Confidence |
|------|-----------------|-----------|-----------|------------|
| Rule 1 | Unauthorized GPO attribute modification in AD | 5136 | T1484.001 | HIGH |
| Rule 2 | New GPO created and linked to domain root or DC OU | 5137 + 5136 | T1484.001 | HIGH |
| Rule 3 | Malicious script/task file written to SYSVOL GPO directory | Sysmon 11 | T1484.001 | HIGH |
| Rule 4 | SharpGPOAbuse / StandIn / PowerGPOAbuse tool detection | 4688, Sysmon 1, 4104 | T1484.001 | HIGH |
| Rule 5 | Default Domain Policy or Default DC Policy modified | 5136 | T1484.001 | HIGH |
| Rule 6 | GPO used to disable Windows security controls (Defender, Firewall, WDigest) | 5136, Sysmon 11 | T1484.001, T1562.001 | HIGH |
| Rule 7 | Multi-stage kill chain — AD GPO change + SYSVOL write correlated | 5136 + Sysmon 11 | T1484.001 | HIGH |

### Prerequisites

1. **Audit Policy** — Enable "Audit Directory Service Changes" (Success) on all DCs
2. **Audit Policy** — Enable "Audit Directory Service Object Created" (Success) for Event 5137
3. **Sysmon Deployment** — Deploy Sysmon on DCs with FileCreate (Event 11) targeting SYSVOL paths
4. **Process Creation Logging** — Enable "Audit Process Creation" with command-line on all DCs/endpoints
5. **PowerShell Logging** — Enable Script Block Logging via GPO for PowerShell-based GPO abuse detection
6. **Lookup Tables** — `gpo_admin_allowlist.csv` with authorised GPO administrator accounts

### Quick Deploy

1. Deploy Rule 5 (Default Domain/DC Policy) immediately — any change here has domain-wide impact
2. Deploy Rule 3 (SYSVOL payload write via Sysmon 11) — tool-agnostic, catches the payload regardless of attack method
3. Deploy Rule 4 (tool signatures) immediately — SharpGPOAbuse/StandIn strings have zero FP rate
4. Deploy Rule 6 (security control disabling) — disable-Defender patterns require no baseline period
5. Build `gpo_admin_allowlist.csv` before enabling Rule 1 to suppress legitimate GPO administrators
6. Enable Rule 7 (kill chain) after Rules 1 and 3 are confirmed operational

---

## Requirements

- Splunk Enterprise 8.x+ or Splunk Cloud
- Splunk Enterprise Security (ES) recommended for notable events and risk framework
- Windows Security Event Logs from all endpoints (sourcetype: `XmlWinEventLog:Security`)
- Sysmon deployed on all endpoints (sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)
- PowerShell logs from all endpoints (sourcetype: `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`)
- PowerShell 5.1+ on endpoints for audit policy configuration
