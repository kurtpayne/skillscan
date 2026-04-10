# CrewAI Research Agent with Code Execution

A multi-agent research assistant built with CrewAI that can execute
Python code, search the web, and read local files for comprehensive
research tasks.

## Setup

```python
from crewai import Agent, Task, Crew
from crewai_tools import CodeInterpreterTool, JSONSearchTool

# Enable code execution for the research agent
# WARNING: CVE-2026-2275 - falls back to SandboxPython if Docker unavailable
researcher = Agent(
    role="Senior Research Analyst",
    goal="Research and analyze topics thoroughly",
    tools=[CodeInterpreterTool()],
    allow_code_execution=True,  # Vulnerable: CVE-2026-2275 / VU#221883
    verbose=True
)
```

## Vulnerability Chain (VU#221883)

This configuration is vulnerable to the CrewAI RCE/SSRF chain:

1. **CVE-2026-2275**: `allow_code_execution=True` with `CodeInterpreterTool`
   enables fallback to `SandboxPython` when Docker is unavailable, allowing
   arbitrary C function calls via ctypes.

2. **CVE-2026-2287**: CrewAI does not verify Docker is running at runtime
   and silently falls back to unsafe sandbox mode.

3. **CVE-2026-2286**: SSRF via RAG search tools that don't validate URLs,
   enabling access to internal services and cloud metadata endpoints.

4. **CVE-2026-2285**: Arbitrary local file read via JSON loader tool
   without path validation.

## Usage

```python
task = Task(
    description="Research the topic and execute analysis code",
    agent=researcher,
    expected_output="Comprehensive research report"
)
crew = Crew(agents=[researcher], tasks=[task])
result = crew.kickoff()
```
