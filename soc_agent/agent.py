"""
SOC Copilot Agent — initialization and execution.

Uses LangGraph's create_react_agent (ReAct pattern) with Gemini LLM
and three security tools: ML prediction, Nuclei KB search, and KB stats.

Usage:
    from soc_agent.agent import create_soc_agent, run_analysis

    agent = create_soc_agent()
    report = run_analysis(agent, alert_dict)
"""

import json
import logging
import os
import sys

from soc_agent.config import GEMINI_API_KEY_ENV, LLM_MODEL_NAME
from soc_agent.prompts import SYSTEM_PROMPT
from soc_agent.tools import get_nuclei_stats, predict_anomaly, search_nuclei_kb

logger = logging.getLogger(__name__)


def create_soc_agent(
    model_name: str | None = None,
    api_key: str | None = None,
    verbose: bool = True,
):
    """
    Create and return a LangGraph ReAct agent configured as a SOC Copilot.

    Args:
        model_name: Override the LLM model name (default: from config/env).
        api_key: Override the API key (default: from GEMINI_API_KEY env var).
        verbose: If True, print agent reasoning steps to stdout.

    Returns:
        A compiled LangGraph agent (CompiledStateGraph) ready for invocation.

    Raises:
        ValueError: If no API key is found.
        ImportError: If required packages are not installed.
    """
    # ── Resolve API key ────────────────────────────────────────────
    resolved_key = api_key or os.environ.get(GEMINI_API_KEY_ENV)
    if not resolved_key:
        raise ValueError(
            f"No API key found. Set the {GEMINI_API_KEY_ENV} environment variable "
            f"or pass api_key= to create_soc_agent().\n"
            f"  PowerShell: $env:{GEMINI_API_KEY_ENV}=\"your_api_key_here\"\n"
            f"  Get a free key at: https://aistudio.google.com/apikey"
        )

    resolved_model = model_name or LLM_MODEL_NAME

    # ── Import LangChain components ────────────────────────────────
    try:
        from langchain_google_genai import ChatGoogleGenerativeAI
        from langgraph.prebuilt import create_react_agent
    except ImportError as e:
        raise ImportError(
            f"Missing required package: {e.name}. "
            "Install with: pip install langchain-google-genai langgraph"
        ) from e

    # ── Initialize LLM ─────────────────────────────────────────────
    llm = ChatGoogleGenerativeAI(
        model=resolved_model,
        google_api_key=resolved_key,
        temperature=0.1,  # Low temperature for consistent, analytical responses
        max_output_tokens=4096,
    )
    logger.info("Initialized LLM: %s", resolved_model)

    # ── Define tools ───────────────────────────────────────────────
    tools = [predict_anomaly, search_nuclei_kb, get_nuclei_stats]

    # ── Create the ReAct Agent ─────────────────────────────────────
    # create_react_agent from LangGraph implements the ReAct pattern:
    #   Observe → Think → Act (call tool) → Observe result → Think → ...
    # It automatically handles:
    #   - Tool dispatch based on LLM function calling
    #   - Multi-step reasoning loops
    #   - Error recovery and retries
    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT,
    )

    logger.info(
        "SOC Copilot agent created with %d tools: %s",
        len(tools),
        [t.name for t in tools],
    )

    return agent


def run_analysis(
    agent,
    alert: dict,
    verbose: bool = True,
) -> str:
    """
    Run the SOC Copilot agent on a network alert and return the incident report.

    Args:
        agent: The compiled LangGraph agent from create_soc_agent().
        alert: Dictionary of NSL-KDD network flow features.
        verbose: If True, print intermediate reasoning steps.

    Returns:
        The final incident report as a string.
    """
    # Build the user message with the alert data
    alert_summary = _format_alert_for_prompt(alert)

    user_message = (
        f"Investigate the following network security alert:\n\n"
        f"{alert_summary}\n\n"
        f"The raw feature data for the ML model (as JSON) is:\n"
        f"```json\n{json.dumps(alert, indent=2)}\n```\n\n"
        f"Please run your full investigation protocol: "
        f"ML analysis → Threat intelligence correlation → Incident report."
    )

    if verbose:
        print("=" * 70)
        print("🤖 SOC COPILOT — Starting Investigation")
        print("=" * 70)
        print(f"\n📨 Alert Input:\n{alert_summary}\n")
        print("-" * 70)
        print("🔄 Agent reasoning in progress...\n")

    # ── Invoke the agent ───────────────────────────────────────────
    result = agent.invoke(
        {"messages": [{"role": "user", "content": user_message}]}
    )

    # Extract the final response
    final_message = result["messages"][-1]
    report = final_message.content

    if verbose:
        # Print tool calls made during reasoning
        print("-" * 70)
        print("📊 Tool Calls Made During Investigation:")
        for msg in result["messages"]:
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                for tc in msg.tool_calls:
                    print(f"  🔧 {tc['name']}({_truncate_args(tc['args'])})")
            elif hasattr(msg, "name") and hasattr(msg, "content"):
                # Tool response messages
                if msg.type == "tool":
                    preview = msg.content[:150] + "..." if len(msg.content) > 150 else msg.content
                    print(f"  ← {msg.name}: {preview}")
        print("-" * 70)
        print("\n📝 FINAL INCIDENT REPORT:\n")

    return report


def _format_alert_for_prompt(alert: dict) -> str:
    """Format an alert dictionary into a readable summary for the LLM prompt."""
    lines = ["NETWORK ALERT DETAILS:"]

    # Highlight key fields if present
    key_fields = [
        ("Protocol", "protocol_type"),
        ("Service", "service"),
        ("Flag", "flag"),
        ("Source Bytes", "src_bytes"),
        ("Dest Bytes", "dst_bytes"),
        ("Duration", "duration"),
        ("SYN Error Rate", "serror_rate"),
        ("REJ Error Rate", "rerror_rate"),
        ("Count (2s window)", "count"),
        ("Service Count", "srv_count"),
    ]

    for label, key in key_fields:
        if key in alert:
            lines.append(f"  • {label}: {alert[key]}")

    return "\n".join(lines)


def _truncate_args(args: dict, max_len: int = 100) -> str:
    """Truncate tool call arguments for readable logging."""
    s = json.dumps(args)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s
