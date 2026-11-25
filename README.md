# SOC Agent Crew — Bare-Metal Ubuntu Detection Engineering Lab

Hands-on Blue Team SOC and Detection Engineering homelab built on bare-metal Ubuntu Linux, combining enterprise SIEM telemetry (Splunk Enterprise), custom SPL/Regex threat detections, Python/Pandas offline triage tooling, and local air-gapped LLM infrastructure.

## Lab Architecture
- **Host OS:** Ubuntu Linux Workstation
- **SIEM:** Bare-metal Splunk Enterprise (`/opt/splunk`), continuously ingesting `/var/log/auth.log` (`sourcetype=syslog`)
- **Local AI Stack:** Ollama (`nemotron-3.5-lightning:30b`, `nemotron-3.5-bolt:e4b`, `gemma4:26b`, `hermes3:8b`, `llama3.1:8b`) orchestrated via Open WebUI for privacy-first log analysis
- **Development:** Python 3 (`venv`, OOP, Pandas), SQL, Bash, and Git OPSEC

## Included Detections

### 1. Autonomous Agent Machine-Speed Command Burst (`artex_agent_burst_detection.spl`)
Inspired by **FBI FLASH-20261113-001 (ARTEX Autonomous Penetration Testing Framework)**, which documented LLM-driven attack agents executing rapid-fire reconnaissance and privilege escalation commands within seconds alongside structured verification markers.
- **Telemetry:** `/var/log/auth.log` (`process="sudo"`)
- **Technique:** Inline Splunk `rex` extraction for `sudo_user` and `executed_cmd`, 5-second time bucketing (`bucket _time span=5s`), and threshold alerting (`command_burst_count >= 4`).
- **Validation:** Verified locally via controlled sub-second `sudo` reconnaissance burst simulation.

### 2. Sliding-Window Sudo Burst & SSH Brute-Force Engine (`auth_log_triage.py`)
Offline Python OOP + Pandas detection engine replicating and expanding the ARTEX behavioral pattern directly against Ubuntu ISO-8601 `/var/log/auth.log` telemetry using least-privilege `adm` group access.
- **MITRE ATT&CK Coverage:** `T1548.003` (Sudo and Sudo Caching — high-velocity command bursts) and `T1110.001` (Brute Force: Password Guessing — failed SSH authentication bursts).
- **Tier 2 Engineering Improvements:**
  - **True Rolling Time Windows:** Uses Pandas `.rolling()` windows instead of fixed time buckets to prevent boundary-straddling evasion.
  - **Incident Coalescing:** Merges overlapping threshold triggers inside a single burst into one clean alert to eliminate SOC queue spam.
  - **Transparent BTP Tuning:** Applies narrow command-pattern allowlisting (never broad user-level exemptions) with suppressed event counters and a `--no-allowlist` audit toggle.

#### Quickstart (Reproducible Test Harness)
~~~bash
python3 -m venv venv && source venv/bin/activate
pip install pandas

# Run against included test harness (boundary-straddling ARTEX burst, BTP installer burst, and SSH brute-force)
python3 auth_log_triage.py -f sample_auth.log

# Audit raw unfiltered alerts without benign command suppression
python3 auth_log_triage.py -f sample_auth.log --no-allowlist

# Run live against local Ubuntu auth.log (requires adm group membership) and export CSV
python3 auth_log_triage.py --export alerts.csv
~~~

## Active Roadmap
- [x] Python/Pandas automated log parser for offline brute-force and privilege escalation triage
- [ ] Local SQL threat-hunting dataset correlating authentication anomalies
- [ ] Sigma rule translations for SIEM portability
- [ ] Linux `auditd` process-tree correlation to separate interactive shells from non-interactive automation
