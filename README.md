# SOC Agent Crew — Bare-Metal Ubuntu Detection Engineering Lab

Hands-on Blue Team SOC and Detection Engineering homelab built on bare-metal Ubuntu Linux, combining enterprise SIEM telemetry (Splunk Enterprise), custom SPL/Regex threat detections, and local air-gapped LLM infrastructure.

## Lab Architecture
* **Host OS:** Ubuntu Linux Workstation
* **SIEM:** Bare-metal Splunk Enterprise (`/opt/splunk`), continuously ingesting `/var/log/auth.log` (`sourcetype=syslog`)
* **Local AI Stack:** Ollama (`hermes3:8b`, `llama3.1:8b`, `gemma4:26b`) orchestrated via Docker & Open WebUI for privacy-first log analysis
* **Development:** Python 3 (`venv`, OOP, Pandas), SQL, Bash, and Git OPSEC

## Included Detections

### 1. Autonomous Agent Machine-Speed Command Burst (`artex_agent_burst_detection.spl`)
Inspired by **FBI FLASH-20261113-001 (ARTEX Autonomous Penetration Testing Framework)**, which documented LLM-driven attack agents executing rapid-fire reconnaissance and privilege escalation commands within seconds alongside structured verification markers.
* **Telemetry:** `/var/log/auth.log` (`process="sudo"`)
* **Technique:** Inline Splunk `rex` extraction for `sudo_user` and `executed_cmd`, 5-second time bucketing (`bucket _time span=5s`), and threshold alerting (`command_burst_count >= 4`).
* **Validation:** Verified locally via controlled sub-second `sudo` reconnaissance burst simulation.

## Active Roadmap
* Python/Pandas automated log parser for offline brute-force and privilege escalation triage
* Local SQL threat-hunting dataset correlating authentication anomalies
* Sigma rule translations for SIEM portability
