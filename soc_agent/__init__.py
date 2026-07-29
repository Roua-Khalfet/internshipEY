"""
soc_agent — LangChain-powered SOC Copilot Agent.

An AI agent that acts as a Senior SOC Analyst, combining:
  - XGBoost ML model predictions (anomaly detection)
  - Nuclei vulnerability knowledge base lookups
  - LLM reasoning and synthesis (Gemini)

Modules:
    config         : Centralized paths and constants
    preprocessing  : NSL-KDD feature encoding & scaling pipeline
    tools          : LangChain @tool wrappers for ML + Nuclei KB
    prompts        : Agent system prompt
    agent          : Agent initialization and execution
"""

__version__ = "1.0.0"
