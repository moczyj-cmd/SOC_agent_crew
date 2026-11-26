import asyncio
import sys
from pathlib import Path
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process

# ---------------------------------------------------------
# 1. THE DATA STRUCTURE (Pydantic)
# Enforces structured SOC output for downstream SIEM/SOAR use.
# ---------------------------------------------------------
class ThreatReport(BaseModel):
    timestamp: str = Field(description="ISO-8601 or syslog timestamp of the anomaly")
    source_ip: str = Field(description="Malicious IP address, or 'local' if host-based privilege escalation")
    attack_type: str = Field(description="Attack classification and MITRE ATT&CK ID (e.g., T1548.003 Sudo Burst, T1110.001 SSH Brute Force)")
    severity: str = Field(description="Low, Medium, High, or Critical")
    summary: str = Field(description="Concise 1-2 sentence Tier 2 triage assessment and recommended containment action")

# ---------------------------------------------------------
# 2. OBSIDIAN VAULT INTEGRATION
# ---------------------------------------------------------
VAULT_PATH = Path.home() / "Documents" / "Obsidian_Local" / "Agent_Profiles"

def load_profile(filename: str) -> str:
    profile_file = VAULT_PATH / filename
    if not profile_file.exists():
        raise FileNotFoundError(f"Missing Obsidian profile: {profile_file}")
    return profile_file.read_text(encoding="utf-8")

# ---------------------------------------------------------
# 3. ASYNCHRONOUS ENGINE (asyncio)
# ---------------------------------------------------------
async def run_soc_analysis(log_sample: str | None = None):
    print("Initiating Local SOC Agent Architecture...")
    print("Models Loaded: Hermes 3 8B (Manager) & Nemotron-3.5-Bolt E4B (Analyst)\n")

    print("Establishing secure uplink to Obsidian Command Center...")
    manager_blueprint = load_profile("Hermes_Manager.md")
    analyst_blueprint = load_profile("Nemotron_Threat_Analyst.md")

    tier1_analyst = Agent(
        role="Tier 1 Threat Intelligence Analyst",
        goal="Parse raw Linux auth/network logs, identify anomalies, and map to MITRE ATT&CK.",
        backstory=analyst_blueprint,
        llm="ollama/nemotron-3.5-bolt:e4b",
        allow_delegation=False,
        verbose=True,
    )

    soc_manager = Agent(
        role="Lead SOC Incident Response Manager",
        goal="Validate Tier 1 findings and compile zero-fluff structured security briefings.",
        backstory=manager_blueprint,
        llm="ollama/hermes3:8b",
        allow_delegation=True,
        verbose=True,
    )

    print("SUCCESS: Agents successfully instantiated and armed with Obsidian blueprints!")
    print(f"Manager Blueprint loaded: {len(manager_blueprint)} characters")
    print(f"Analyst Blueprint loaded: {len(analyst_blueprint)} characters\n")

    if not log_sample:
        return

    triage_task = Task(
        description=(
            "Analyze the following Linux security telemetry/alert, extract key indicators, "
            "map to MITRE ATT&CK, and assign severity:\n\n"
            f"{log_sample}"
        ),
        expected_output="Structured ThreatReport with timestamp, source_ip, attack_type, severity, and summary.",
        agent=tier1_analyst,
        output_pydantic=ThreatReport,
    )

    crew = Crew(
        agents=[tier1_analyst, soc_manager],
        tasks=[triage_task],
        process=Process.sequential,
        verbose=True,
    )

    result = await asyncio.to_thread(crew.kickoff)
    print("\n--- Validated ThreatReport ---")
    print(result.pydantic.model_dump_json(indent=2) if result.pydantic else result.raw)

if __name__ == "__main__":
    sample = " ".join(sys.argv[1:]).strip() or None
    asyncio.run(run_soc_analysis(sample))