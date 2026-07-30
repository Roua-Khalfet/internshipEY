"""
soc_agent — LangChain-powered SOC Copilot Agent.

An AI agent that acts as a Senior SOC Analyst, combining:
  - XGBoost ML pipeline predictions (anomaly detection)
  - Nuclei vulnerability knowledge base lookups
  - LLM reasoning and synthesis (Groq / Gemini)

Modules:
    config         : Centralized paths and constants
    tools          : LangChain @tool wrappers for ML + Nuclei KB
    prompts        : Agent system prompt
    agent          : Agent initialization and execution
"""

__version__ = "2.0.0"
