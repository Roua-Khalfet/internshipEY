"""
SOC Copilot — Demo Entry Point.

Simulates incoming network alerts and runs them through the AI agent
for full investigation (ML prediction → Nuclei KB correlation → Incident Report).

Usage:
    python scripts/run_soc_copilot.py                    # Run all 3 test scenarios
    python scripts/run_soc_copilot.py --scenario 1       # Run specific scenario
    python scripts/run_soc_copilot.py --scenario 2 -q    # Quiet mode (no verbose)

Prerequisites:
    1. Set your API key:  $env:GEMINI_API_KEY="your_key"
    2. Run preprocessors:  python scripts/save_preprocessors.py
    3. Ensure nuclei_kb.db exists:  python scripts/run_pipeline.py
"""

import argparse
import json
import logging
import sys
import time
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load environment variables from .env (if present)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    # If python-dotenv is not installed, scripts will still work when env vars are set externally
    pass


# ═══════════════════════════════════════════════════════════════════
# Test Scenarios — Simulated Network Alerts
# ═══════════════════════════════════════════════════════════════════

SCENARIOS = {
    1: {
        "name": "🔴 SYN Flood / DoS Attack on HTTP",
        "description": (
            "Massive volume of SYN requests targeting an HTTP service. "
            "High connection count with 100% SYN error rate — classic SYN flood."
        ),
        "alert": {
            "duration": 0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "S0",         # SYN only, no response (half-open)
            "src_bytes": 0,
            "dst_bytes": 0,
            "wrong_fragment": 0,
            "hot": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "count": 511,         # Very high: 511 connections in 2 seconds
            "srv_count": 511,
            "serror_rate": 1.0,   # 100% SYN errors
            "srv_serror_rate": 1.0,
            "rerror_rate": 0.0,
        },
    },
    2: {
        "name": "🟠 Suspicious FTP Data Exfiltration",
        "description": (
            "Abnormally large data transfer over FTP with successful login. "
            "High source bytes suggest possible data exfiltration."
        ),
        "alert": {
            "duration": 1024,
            "protocol_type": "tcp",
            "service": "ftp_data",
            "flag": "SF",           # Normal connection termination
            "src_bytes": 58724,     # Very high: ~57KB outbound
            "dst_bytes": 8112,
            "wrong_fragment": 0,
            "hot": 0,
            "logged_in": 1,         # Successfully authenticated
            "num_compromised": 2,   # Compromise indicators
            "count": 3,
            "srv_count": 3,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
        },
    },
    3: {
        "name": "🟡 DNS Tunneling Attempt",
        "description": (
            "Unusual DNS activity with abnormally large request sizes. "
            "DNS requests should be small — large payloads suggest tunneling."
        ),
        "alert": {
            "duration": 0,
            "protocol_type": "udp",
            "service": "domain_u",  # DNS over UDP
            "flag": "SF",
            "src_bytes": 512,       # Large for DNS (normal is ~40-100 bytes)
            "dst_bytes": 1024,      # Very large DNS response
            "wrong_fragment": 0,
            "hot": 0,
            "logged_in": 0,
            "num_compromised": 0,
            "count": 150,           # High frequency of DNS queries
            "srv_count": 150,
            "serror_rate": 0.0,
            "srv_serror_rate": 0.0,
            "rerror_rate": 0.0,
        },
    },
}


def run_scenario(scenario_id: int, verbose: bool = True):
    """Run a single test scenario through the SOC Copilot agent."""
    from soc_agent.agent import create_soc_agent, run_analysis

    scenario = SCENARIOS[scenario_id]

    print("\n" + "█" * 70)
    print(f"█  SCENARIO {scenario_id}: {scenario['name']}")
    print(f"█  {scenario['description']}")
    print("█" * 70)
    print(f"\n📋 Alert Features:\n{json.dumps(scenario['alert'], indent=2)}\n")

    # Create the agent (reuses cached LLM connection)
    agent = create_soc_agent(verbose=verbose)

    # Run the investigation
    start_time = time.time()
    report = run_analysis(agent, scenario["alert"], verbose=verbose)
    elapsed = time.time() - start_time

    print(report)
    print(f"\n⏱️  Investigation completed in {elapsed:.1f}s")
    print("=" * 70)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="SOC Copilot — AI-Powered Intrusion Detection Agent"
    )
    parser.add_argument(
        "--scenario", "-s",
        type=int,
        choices=[1, 2, 3],
        help="Run a specific scenario (1=SYN Flood, 2=FTP Exfil, 3=DNS Tunnel). "
             "Default: run all.",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode — suppress verbose agent reasoning output.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override the LLM model name (default: gemini-2.0-flash).",
    )
    args = parser.parse_args()

    # Configure logging
    log_level = logging.WARNING if args.quiet else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    # Override model if specified
    if args.model:
        import soc_agent.config as cfg
        cfg.LLM_MODEL_NAME = args.model

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║          🤖 SOC COPILOT — AI Security Agent                ║")
    print("║          Powered by LangChain + Gemini + XGBoost           ║")
    print("╚══════════════════════════════════════════════════════════════╝")

    if args.scenario:
        run_scenario(args.scenario, verbose=not args.quiet)
    else:
        # Run all scenarios
        for scenario_id in SCENARIOS:
            try:
                run_scenario(scenario_id, verbose=not args.quiet)
            except Exception as e:
                print(f"\n❌ Scenario {scenario_id} failed: {e}")
                logging.exception("Scenario %d failed", scenario_id)
                continue

    print("\n✅ All investigations complete.")


if __name__ == "__main__":
    main()
