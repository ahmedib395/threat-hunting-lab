# Automated Threat Hunting Lab with Detection-as-Code

![Detection Engineering](https://img.shields.io/badge/Detection-Engineering-blue)
![Sigma Rules](https://img.shields.io/badge/Sigma-Rules-brightgreen)
![GitHub Actions](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-orange)
![Wazuh SIEM](https://img.shields.io/badge/SIEM-Wazuh-red)

## Overview

A production-grade security detection pipeline demonstrating **detection-as-code** principles. This project showcases:
- 10 vendor-neutral Sigma detection rules
- GitHub Actions CI/CD pipeline for automated rule validation and conversion
- Wazuh SIEM deployment with real-time attack detection
- MITRE ATT&CK technique mapping across the attack lifecycle
- End-to-end testing with Atomic Red Team attack simulation

## Architecture

GitHub (CI) → Wazuh Manager (CD) → Detection & Alerting
Sigma YAML Rules Local Rules XML Real-time Alerts
Converter Script Sysmon Logs Dashboard Visualization
Validation Pipeline Windows Endpoint


## 10 Detection Rules

| ID | Technique | Description | Status |
|----|-----------|-------------|--------|
| 100001 | T1010 | Application Window Discovery | ✅ Tested |
| 100002 | T1036 | Masquerading - Suspicious Location | ✅ Tested |
| 100003 | T1047 | Windows Management Instrumentation | ✅ Tested |
| 100004 | T1049 | System Network Connections Discovery | ✅ Tested |
| 100005 | T1053 | Scheduled Task Creation for Persistence | ✅ Ready |
| 100006 | T1057 | Process Discovery | ✅ Ready |
| 100007 | T1059.003 | Suspicious Command Shell Execution | ✅ Ready |
| 100008 | T1083 | File and Directory Discovery | ✅ Ready |
| 100009 | T1547 | Registry Run Key Modification | ✅ Ready |
| 100010 | T1547.001 | Driver Installation for Persistence | ✅ Ready |

## Workflow: CI/CD Pipeline

### Continuous Integration (GitHub Actions)
1. **Trigger**: Push to `sigma-rules/` folder
2. **Validate**: YAML syntax check on all Sigma rules
3. **Convert**: Sigma YAML → Wazuh XML format
4. **Generate**: Production-ready artifact (`wazuh_rules.xml`)
5. **Output**: Downloadable from GitHub Actions run

### Continuous Deployment (Manual, Auditable)
1. Download artifact from GitHub Actions
2. Paste XML into Wazuh Dashboard (Stack Management → Rules → local_rules.xml)
3. Restart Wazuh Manager
4. Rules load and begin detecting attacks in real-time

**Why Manual CD?** Enterprise-standard practice — detection rules are security-critical. Manual deployment ensures review before production.

## Detection Pipeline

Attack on Victim VM
↓
Sysmon captures event (Event ID 1, 13)
↓
Wazuh Agent forwards to Manager
↓
Custom Sigma-derived rules evaluate event
↓
Rule match → Alert generated
↓
Wazuh Dashboard displays alert with MITRE mapping


## Skills Demonstrated

- **Detection Engineering**: Writing vendor-neutral Sigma rules
- **SIEM Administration**: Wazuh configuration and rule deployment
- **Automation**: GitHub Actions CI/CD pipeline
- **Infrastructure-as-Code**: Rules as version-controlled YAML
- **Security Operations**: MITRE ATT&CK mapping, attack simulation
- **System Integration**: Sysmon → Wazuh → Detection pipeline

## Tools & Technologies

| Component | Purpose |
|-----------|---------|
| **Sigma** | Vendor-neutral detection rule format |
| **Python** | Rule converter (YAML → XML) |
| **GitHub Actions** | Automated validation & conversion |
| **Wazuh** | SIEM for centralized detection |
| **Docker** | Container-based Wazuh deployment |
| **Sysmon** | Windows system monitoring |
| **Atomic Red Team** | Attack simulation for testing |

## Project Structure

threat-hunting-lab/
├── sigma-rules/ # 10 vendor-neutral Sigma YAML rules
│ ├── T1010_Application_Window_Discovery.yml
│ ├── T1036_Masquerading.yml
│ ├── T1047_WMI_Execution.yml
│ └── ... (7 more rules)
├── sigma_to_wazuh_converter.py # Production converter script
├── .github/workflows/
│ └── validate-sigma-rules.yml # GitHub Actions CI pipeline
├── README.md # This file
└── wazuh-rules/
└── local_rules.xml # Deployed Wazuh rules (generated)


## Running the Lab

### Prerequisites
- Windows 10 VM with Sysmon installed
- Wazuh Manager running (Docker recommended)
- Wazuh Agent on Windows endpoint

### Deploy Rules
1. GitHub Actions automatically converts Sigma rules on commit
2. Download `wazuh_rules.xml` artifact
3. Paste into Wazuh Dashboard local_rules.xml
4. Restart Wazuh: `docker restart single-node-wazuh.manager-1`

### Test Detection
```powershell
# Run attack simulation on victim VM
Import-Module 'C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1' -Force
Invoke-AtomicTest T1010 -TestNumbers 1
```

### Verify in Wazuh
- Dashboard → Discover
- Filter by `rule.id: 100001` (or any custom rule)
- Observe real-time alert firing

## Converter Features

The `sigma_to_wazuh_converter.py` script:
- ✅ Reads Sigma YAML rules from `sigma-rules/` folder
- ✅ Extracts MITRE ATT&CK technique IDs automatically
- ✅ Normalizes field names for Wazuh compatibility
- ✅ Assigns correct Event IDs (1 for process, 13 for registry)
- ✅ Combines multiple detection conditions with OR logic
- ✅ Generates production-ready XML with proper formatting
- ✅ Writes artifact for GitHub Actions upload

## Future Work (v1.1)

- [ ] GitHub API direct deployment to Wazuh
- [ ] Expand to 20+ detection rules
- [ ] Add false-positive tuning based on benign activity
- [ ] Automated alert correlation and incident generation
- [ ] Sigma rule testing framework

## Known Limitations

- Manual deployment to Wazuh (v1.1 will add API automation)
- 10 rules cover common ATT&CK techniques (expansion roadmap available)
- False-positive tuning required for production (environment-specific)

## Author

**Ahmed** | Detection Engineering Portfolio Project

## License

This project is provided as-is for educational and demonstration purposes.

---

**This project demonstrates production-grade security detection engineering and DevOps automation.**
