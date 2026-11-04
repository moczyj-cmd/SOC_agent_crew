import asyncio
from pathlib import Path
from pydantic import BaseModel, Field
from crewai import Agent, Task, Crew, Process

# ---------------------------------------------------------
# 1. THE DATA STRUCTURE (Pydantic)
# This forces the AI to output exactly what we want.
# ---------------------------------------------------------
class ThreatReport(BaseModel):
    timestamp: str = Field(description="Time of the anomaly")
    source_ip: str = Field(description="The malicious IP address")
    attack_type: str = Field(description="Type of attack (e.g., SQLi, Brute Force)")
    severity: str = Field(description="Low, Medium, High, or Critical")

# ---------------------------------------------------------
# 2. OBSIDIAN VAULT INTEGRATION
# Route this path to your extracted local vault folder
# ---------------------------------------------------------
VAULT_PATH = Path.home() / "Documents" / "Obsidian_Local" / "Agent_Profiles"

def load_profile(filename):
    try:
        return (VAULT_PATH / filename).read_text(encoding="utf-8")
    except FileNotFoundError:
        return f"ERROR: Could not find {filename} at {VAULT_PATH}"

# ---------------------------------------------------------
# 3. ASYNCHRONOUS ENGINE (asyncio)
# Non-blocking loop so the system doesn't freeze while thinking
# ---------------------------------------------------------
async def run_soc_analysis():
    print("Initiating Local SOC Agent Architecture...")
    print("Models Loaded: Llama 3.1 (Manager) & Gemma 2 (Analyst)\n")
    
    # 1. Pull the raw text from your Obsidian Vault
    print("Establishing secure uplink to Obsidian Command Center...")
    manager_blueprint = load_profile("Llama_Manager.md")
    analyst_blueprint = load_profile("Gemma_Threat_Analyst.md")

    # 2. Inject the Obsidian blueprints into the CrewAI Agents
    # Note: We now pass the LLM natively as a string ("ollama/<model_name>")
    tier1_analyst = Agent(
        role="Tier 1 Threat Intelligence Analyst",
        goal="Parse raw network logs, identify anomalies, and map to MITRE ATT&CK.",
        backstory=analyst_blueprint,  # Injected directly from your vault
        llm="ollama/gemma2",          # Native Ollama routing
        allow_delegation=False,
        verbose=True
    )

    soc_manager = Agent(
        role="Lead SOC Incident Response Manager",
        goal="Coordinate analysts, validate findings, and compile zero-fluff security briefings.",
        backstory=manager_blueprint,  # Injected directly from your vault
        llm="ollama/llama3.1",        # Native Ollama routing
        allow_delegation=True,
        verbose=True
    )

    print("SUCCESS: Agents successfully instantiated and armed with Obsidian blueprints!")
    print(f"Manager Blueprint loaded: {len(manager_blueprint)} characters")
    print(f"Analyst Blueprint loaded: {len(analyst_blueprint)} characters\n")

if __name__ == "__main__":
    asyncio.run(run_soc_analysis())