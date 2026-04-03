# CLAUDE.md — Detection Engineering

## Project Overview

Splunk SIEM detection rules for SOC attack detection and incident response. **164 detection rules** across 12 categories covering Windows, Active Directory, RHEL Linux, Apache, ICS/OT, network firewalls (Palo Alto, Cisco, Fortinet, Check Point), EDR platforms (CrowdStrike, Microsoft Defender, Trend Micro), credential access attacks, network security threats, and recent threat campaigns.

Every rule includes SPL search queries, MITRE ATT&CK mapping, severity/confidence scoring, throttle configuration, notable event generation, and recommended response actions.

**Repository**: https://github.com/Krishcalin/Detection-Engineering
**License**: MIT
**Platform**: Splunk Enterprise / Splunk Cloud (ES compatible)

## Rule Inventory

### By Category

| Category | Directory | Files | Rules | Focus Areas |
|----------|-----------|------:|------:|-------------|
| **Windows** | `splunk_rules/windows/` | 12 | 100 | Execution, persistence, priv esc, defense evasion, discovery, lateral movement, C2, collection, exfiltration, impact, LOLBin proxy execution, account manipulation, anti-forensics |
| **Active Directory** | `splunk_rules/active_directory/` | 3 | 23 | BloodHound, AS-REP roasting, PetitPotam, ADIDNS, Silver/Diamond Ticket, DCShadow, SID History, Shadow Credentials, RBCD, AdminSDHolder, Skeleton Key, overpass-the-hash, DPAPI, GPO abuse |
| **Credential Access** | `splunk_rules/credential_access/` | 11 | 75 | Kerberoasting, Golden Ticket, DCSync, LSASS dumping, PtH, NTLM relay, AD CS attacks, GPO modification, NTDS.dit, password spraying |
| **RHEL Linux** | `splunk_rules/rhel_linux/` | 8 | 63 | Execution, persistence, priv esc, defense evasion, discovery, lateral movement, credential access, exfiltration |
| **Apache Web Server** | `splunk_rules/apache_webserver/` | 6 | 37 | Brute force, DoS, exploitation, path traversal, SQLi, XSS, web shells |
| **ICS/OT** | `splunk_rules/ics_ot/` | 3 | 20 | IT-to-OT zone breach, Modbus/DNP3/S7comm/OPC UA, TRITON, Industroyer, PIPEDREAM, safety bypass, rogue devices, process anomalies, alarm manipulation |
| **Network Firewalls** | `splunk_rules/network_firewalls/` | 4 | 30 | Palo Alto (PAN-OS CVEs, GlobalProtect), Cisco ASA/FTD (ArcaneDoor), Fortinet (FortiJump, SSL-VPN), Check Point (SmartConsole, blades) |
| **EDR Detection** | `splunk_rules/edr_detection/` | 3 | 24 | CrowdStrike Falcon (sensor tamper, C2, ransomware), Microsoft Defender (AMSI, ASR, macros), Trend Micro (agent tamper, IPS, integrity monitoring) |
| **Network Security** | `splunk_rules/network_security/` | 1 | 6 | TOR traffic, rogue DNS, large uploads/exfiltration, unencrypted sensitive traffic, network share removal, recurring malware |
| **Recent Attacks** | `splunk_rules/recent_attacks/` | 1 | 12 | CVE-2026-21509, APT28 Operation NeuSploit |

**Total: 52 files, 164+ rules, ~42,000 lines of YAML**

### ICS/OT Protocol Coverage

| Protocol | Port | Rules | Attacks Detected |
|----------|------|------:|-----------------|
| Modbus TCP | 502 | 3 | Unauthorized writes, rogue clients, register manipulation |
| DNP3 | 20000 | 1 | Unauthorized control commands (CROB, restart) |
| S7comm (Siemens) | 102 | 1 | Unauthorized PLC programming, firmware download |
| OPC UA | 4840 | 1 | Unauthorized data access, process data exfiltration |
| EtherNet/IP | 44818 | 1 | Protocol scanning, CIP commands |
| BACnet | 47808 | 1 | Protocol scanning |
| TriStation | 1502 | 1 | TRITON/TRISIS SIS attack |
| IEC 60870-5-104 | 2404 | 1 | Industroyer power grid attack |
| Codesys | 1740-1743 | 1 | PIPEDREAM/INCONTROLLER |

### Known Malware/Framework Detection

| Malware/Framework | Category | Rule File |
|-------------------|----------|-----------|
| TRITON/TRISIS | ICS/OT | ics_malware_attack_detection.yml |
| Industroyer/CrashOverride | ICS/OT | ics_malware_attack_detection.yml |
| PIPEDREAM/INCONTROLLER | ICS/OT | ics_malware_attack_detection.yml |
| ArcaneDoor (UAT4356) | Cisco Firewall | cisco_asa_ftd_detection.yml |
| Mimikatz | Credential / EDR | Multiple |
| Rubeus | Credential / EDR | Multiple |
| Cobalt Strike | EDR | crowdstrike_falcon_detection.yml |
| BloodHound/SharpHound | Active Directory | ad_initial_access_reconnaissance.yml |
| Responder | Active Directory | ad_initial_access_reconnaissance.yml |

## Rule Structure

Every rule follows a consistent YAML structure:

```yaml
rule_N_descriptive_name:
  name: "Human-readable rule name"
  description: >
    Multi-line description of the attack, why it matters,
    and what the detection covers.
  mitre_attack:
    - T1xxx       # ATT&CK technique ID
    - T1xxx.yyy   # Sub-technique
  severity: critical | high | medium | low | info
  confidence: 0-100

  search: |
    index=<index> sourcetype="<sourcetype>"
    <SPL query>
    | stats count ... BY src_ip
    | where count > threshold

  throttle: field, seconds
  notable:
    rule_title: "Title with $field$ substitutions"
    rule_description: >
      Description with $field$ substitutions for notable event.
    drilldown_search: |       # optional
      <follow-up SPL query>
    recommended_actions:
      - Step-by-step response actions
    remediation_cmd: "command"  # optional — PowerShell/CLI fix command
```

### Key Fields

| Field | Purpose |
|-------|---------|
| `name` | Human-readable title displayed in Splunk ES |
| `mitre_attack` | MITRE ATT&CK technique IDs |
| `severity` | critical, high, medium, low, info |
| `confidence` | 0-100 score for SOC triage prioritization |
| `search` | SPL query — the core detection logic |
| `throttle` | Dedup field + window (seconds) to prevent alert fatigue |
| `notable.rule_title` | Notable event title with `$field$` substitutions |
| `notable.recommended_actions` | Incident response steps for SOC analysts |
| `notable.remediation_cmd` | Fix command (PowerShell, CLI) — optional |

## Data Source Requirements

### Sourcetypes by Category

| Category | Required Sourcetypes |
|----------|---------------------|
| Windows | `XmlWinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` |
| Active Directory | `XmlWinEventLog:Security` (DC), `XmlWinEventLog:DNS-Server` |
| RHEL Linux | `linux:audit`, `syslog`, `linux:syslog` |
| Apache | `apache:access`, `apache:error` |
| ICS/OT | `zeek:conn`, `zeek:modbus`, `zeek:dnp3`, `zeek:s7comm`, `suricata:eve`, `pan:traffic` |
| Palo Alto | `pan:traffic`, `pan:threat`, `pan:system`, `pan:config`, `pan:globalprotect` |
| Cisco ASA/FTD | `cisco:asa`, `cisco:ftd` |
| Fortinet | `fgt_traffic`, `fgt_utm`, `fgt_event`, `fgt_vpn` |
| Check Point | `cp_log` |
| CrowdStrike | `crowdstrike:events:sensor`, `crowdstrike:events:detection` |
| Microsoft Defender | `ms:defender:advanced`, `ms:defender:alerts` |
| Trend Micro | `deepsecurity`, `trendmicro:deep_security` |

### Required Splunk Add-ons

- Splunk Add-on for Microsoft Windows
- Splunk Add-on for Sysmon
- Splunk Add-on for Unix/Linux
- Splunk Add-on for Palo Alto Networks
- Splunk Add-on for Cisco ASA
- Splunk Add-on for Fortinet FortiGate
- Splunk Add-on for Check Point
- Splunk Add-on for CrowdStrike Falcon
- Splunk Add-on for Zeek (Bro)

### Lookup Tables

Rules reference these lookup tables (must be created in your environment):

| Lookup | Fields | Used By |
|--------|--------|---------|
| `domain_controllers` | ip, hostname | AD, credential access |
| `approved_admin_ips` | ip, username, role | Firewalls, AD |
| `ot_asset_inventory` | ip, hostname, device_type, vendor, zone, criticality | ICS/OT |
| `authorized_modbus_clients` | src_ip | ICS/OT |
| `authorized_dnp3_masters` | master_ip | ICS/OT |
| `authorized_engineering_workstations` | ip | ICS/OT |
| `known_good_hashes` | sha256 | EDR |
| `domain_admin_accounts` | samaccountname | AD |
| `approved_crosszone_access` | src_ip, dest_ip | Firewalls, ICS/OT |

## MITRE ATT&CK Coverage

### Tactics Covered

| Tactic | Rule Count | Key Techniques |
|--------|-----------|---------------|
| **Initial Access** | 15+ | T1190 (exploit), T1133 (VPN), T1566 (phishing), T1110 (brute force) |
| **Execution** | 20+ | T1059 (scripting), T1047 (WMI), T1218 (LOLBins), T1053 (scheduled task) |
| **Persistence** | 15+ | T1546 (event triggered), T1098 (account manipulation), T1556 (auth modification) |
| **Privilege Escalation** | 12+ | T1134 (token manipulation), T1484 (domain policy), T1068 (exploitation) |
| **Defense Evasion** | 15+ | T1562 (impair defenses), T1027 (obfuscation), T1036 (masquerading) |
| **Credential Access** | 20+ | T1003 (OS credential dumping), T1558 (Kerberos tickets), T1557 (MITM) |
| **Discovery** | 10+ | T1087 (account discovery), T1069 (group discovery), T1018 (remote system) |
| **Lateral Movement** | 12+ | T1021 (remote services), T1550 (alt auth material), T1570 (tool transfer) |
| **Collection** | 8+ | T0801 (ICS monitor), T0802 (automated collection), T0882 (theft of info) |
| **Exfiltration** | 8+ | T1048 (alt protocol), T1567 (web service) |
| **Impact** | 10+ | T1486 (ransomware), T1490 (inhibit recovery), T0831 (manipulation of control) |

### ICS-Specific Tactics (MITRE ATT&CK for ICS)

| Tactic | Techniques |
|--------|-----------|
| Impair Process Control | T0806, T0831, T0836, T0855 |
| Inhibit Response Function | T0813, T0815, T0837, T0878 |
| Impact | T0826, T0827, T0829, T0882 |

## Development Guidelines

### Adding a New Detection Rule

1. Create a `.yml` file in the appropriate `splunk_rules/<category>/` directory
2. Follow the rule structure template (see Rule Structure above)
3. Include at minimum: `name`, `description`, `mitre_attack`, `severity`, `confidence`, `search`, `throttle`, `notable`
4. Map to specific MITRE ATT&CK technique IDs (not just tactics)
5. Include `recommended_actions` with actionable steps for SOC analysts
6. Set appropriate `throttle` to prevent alert fatigue
7. Test the SPL query against sample data before committing

### Adding a New Category

1. Create directory: `splunk_rules/<category_name>/`
2. Create rule files with descriptive names: `<category>_<focus>_detection.yml`
3. Follow the file header convention (description, MITRE ATT&CK, prerequisites, author)
4. Update this CLAUDE.md with the new category

### Naming Conventions

- **Directories**: `snake_case` (e.g., `active_directory`, `network_firewalls`)
- **Files**: `snake_case_detection.yml` (e.g., `paloalto_detection.yml`)
- **Rule IDs**: `rule_N_descriptive_name` (e.g., `rule_1_process_injection`)
- **MITRE IDs**: Always use full technique ID (e.g., `T1059.001` not just `T1059`)

### Severity Guidelines

| Severity | Criteria |
|----------|---------|
| **critical** | Confirmed exploitation, active compromise, safety system bypass, sensor tampering, ransomware |
| **high** | Likely attack in progress, credential theft, policy tampering, brute force, lateral movement |
| **medium** | Suspicious activity requiring investigation, misconfigurations, policy violations |
| **low** | Informational, reconnaissance, minor policy deviations |

### Confidence Scoring

| Score | Meaning |
|-------|---------|
| 90-100 | Very high — strong IOC match, known malware signatures, EDR sensor alerts |
| 75-89 | High — behavioral detection with low false positive rate |
| 60-74 | Medium — heuristic detection, may require tuning per environment |
| Below 60 | Low — broad behavioral pattern, expect false positives |

## Repository Structure

```
Detection-Engineering/
├── splunk_rules/
│   ├── active_directory/          # AD attack detection (23 rules)
│   │   ├── ad_initial_access_reconnaissance.yml
│   │   ├── ad_persistence_privilege_escalation.yml
│   │   └── ad_lateral_movement_domination.yml
│   ├── apache_webserver/          # Apache attack detection (37 rules)
│   │   ├── apache_brute_force_dos_detection.yml
│   │   ├── apache_exploitation_detection.yml
│   │   ├── apache_path_traversal_detection.yml
│   │   ├── apache_reconnaissance_detection.yml
│   │   ├── apache_sqli_xss_detection.yml
│   │   └── apache_web_shell_detection.yml
│   ├── credential_access/         # Credential theft detection (75 rules)
│   │   ├── adcs_attack_detection.yml
│   │   ├── dcsync_attack_detection.yml
│   │   ├── golden_ticket_attack_detection.yml
│   │   ├── gpo_modification_detection.yml
│   │   ├── kerberoasting_attack_detection.yml
│   │   ├── lsass_credential_dumping_detection.yml
│   │   ├── ntds_dit_extraction_detection.yml
│   │   ├── ntlm_relay_detection.yml
│   │   ├── pass_the_hash_detection.yml
│   │   ├── password_spraying_detection.yml
│   │   └── privileged_group_membership_modification_detection.yml
│   ├── edr_detection/             # EDR platform detection (24 rules)
│   │   ├── crowdstrike_falcon_detection.yml
│   │   ├── microsoft_defender_detection.yml
│   │   └── trendmicro_deep_security_detection.yml
│   ├── ics_ot/                    # ICS/OT attack detection (20 rules)
│   │   ├── ics_network_anomaly_detection.yml
│   │   ├── ics_malware_attack_detection.yml
│   │   └── ics_process_anomaly_detection.yml
│   ├── network_firewalls/         # Firewall detection (30 rules)
│   │   ├── paloalto_detection.yml
│   │   ├── cisco_asa_ftd_detection.yml
│   │   ├── fortinet_fortigate_detection.yml
│   │   └── checkpoint_detection.yml
│   ├── recent_attacks/            # Threat campaign detection (12 rules)
│   │   └── cve_2026_21509_apt28_operation_neusploit_detection.yml
│   ├── rhel_linux/                # RHEL Linux detection (63 rules)
│   │   ├── rhel_credential_access_detection.yml
│   │   ├── rhel_defense_evasion_detection.yml
│   │   ├── rhel_discovery_enumeration_detection.yml
│   │   ├── rhel_execution_detection.yml
│   │   ├── rhel_exfiltration_detection.yml
│   │   ├── rhel_lateral_movement_detection.yml
│   │   ├── rhel_persistence_detection.yml
│   │   └── rhel_privilege_escalation_detection.yml
│   ├── network_security/             # Network threat detection (6 rules)
│   │   └── network_threat_detection.yml
│   └── windows/                   # Windows detection (100 rules)
│       ├── windows_account_manipulation_detection.yml
│       ├── windows_anti_forensics_detection.yml
│       ├── windows_collection_exfiltration_detection.yml
│       ├── windows_command_control_detection.yml
│       ├── windows_defense_evasion_detection.yml
│       ├── windows_discovery_detection.yml
│       ├── windows_execution_detection.yml
│       ├── windows_impact_detection.yml
│       ├── windows_lateral_movement_detection.yml
│       ├── windows_lolbin_proxy_execution_detection.yml
│       ├── windows_persistence_detection.yml
│       └── windows_privilege_escalation_detection.yml
├── Recent_Attacks/                # Threat analysis documentation
├── docs/
│   └── banner.svg                 # Repository banner
├── README.md
├── CLAUDE.md
├── LICENSE                        # MIT
└── .gitignore
```
