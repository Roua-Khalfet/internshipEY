"""
SOC Copilot — FastAPI Backend.

Exposes the ML pipeline, Nuclei KB, and LLM agent as REST API endpoints.

Run:
    cd backend
    uvicorn main:app --reload --port 8000
"""

import json
import logging
import sys
from pathlib import Path

# Add project root to path so we can import soc_agent
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Load .env before importing soc_agent
try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env")
except ImportError:
    pass

from soc_agent.config import (
    CATEGORICAL_FEATURES,
    NUMERIC_FEATURES,
    PIPELINE_FEATURES,
)
from soc_agent.tools import predict_anomaly, search_nuclei_kb, get_nuclei_stats

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

# ── FastAPI App ────────────────────────────────────────────────────
app = FastAPI(
    title="SOC Copilot API",
    description="AI-Powered Intrusion Detection & Threat Intelligence API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request/Response Models ────────────────────────────────────────

class AlertFeatures(BaseModel):
    """Network flow features for ML prediction."""
    protocol_type: str = Field(..., description="e.g. tcp, udp, icmp")
    service: str = Field(..., description="e.g. http, ftp, smtp, private")
    flag: str = Field(..., description="e.g. SF, S0, REJ")
    duration: float = 0
    src_bytes: float = 0
    dst_bytes: float = 0
    land: float = 0
    wrong_fragment: float = 0
    urgent: float = 0
    hot: float = 0
    num_failed_logins: float = 0
    logged_in: float = 0
    num_compromised: float = 0
    root_shell: float = 0
    su_attempted: float = 0
    num_root: float = 0
    num_file_creations: float = 0
    num_shells: float = 0
    num_access_files: float = 0
    num_outbound_cmds: float = 0
    is_host_login: float = 0
    is_guest_login: float = 0
    count: float = 0
    srv_count: float = 0
    serror_rate: float = 0
    srv_serror_rate: float = 0
    rerror_rate: float = 0
    srv_rerror_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0
    srv_diff_host_rate: float = 0
    dst_host_count: float = 0
    dst_host_srv_count: float = 0
    dst_host_same_srv_rate: float = 0
    dst_host_diff_srv_rate: float = 0
    dst_host_same_src_port_rate: float = 0
    dst_host_srv_diff_host_rate: float = 0
    dst_host_serror_rate: float = 0
    dst_host_srv_serror_rate: float = 0
    dst_host_rerror_rate: float = 0
    dst_host_srv_rerror_rate: float = 0


class InvestigateRequest(BaseModel):
    """Request for full LLM agent investigation."""
    alert: AlertFeatures


class NucleiSearchRequest(BaseModel):
    """Request for Nuclei KB search."""
    query: str
    search_type: str = "keyword"


# ── Endpoints ──────────────────────────────────────────────────────

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "SOC Copilot API"}


@app.post("/api/predict")
async def predict(alert: AlertFeatures):
    """Run XGBoost pipeline prediction on network flow features."""
    try:
        alert_dict = alert.model_dump()
        alert_json = json.dumps(alert_dict)
        result = predict_anomaly.invoke({"alert_json": alert_json})
        
        # Parse the structured text result into JSON
        parsed = _parse_prediction_result(result, alert_dict)
        return parsed
    except Exception as e:
        logger.exception("Prediction failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/search-nuclei")
async def search_nuclei(
    query: str = Query(..., description="Search term"),
    search_type: str = Query("keyword", description="keyword|tag|protocol|severity"),
):
    """Search the Nuclei vulnerability knowledge base."""
    try:
        result = search_nuclei_kb.invoke({
            "query": query,
            "search_type": search_type,
        })
        return {"raw": result, "query": query, "search_type": search_type}
    except Exception as e:
        logger.exception("Nuclei search failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/nuclei-stats")
async def nuclei_stats():
    """Get Nuclei KB statistics."""
    try:
        result = get_nuclei_stats.invoke({})
        return {"raw": result}
    except Exception as e:
        logger.exception("Stats failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigate")
async def investigate(request: InvestigateRequest):
    """Run the full LLM agent investigation (ML + Nuclei KB + Report)."""
    try:
        from soc_agent.agent import create_soc_agent, run_analysis

        alert_dict = request.alert.model_dump()
        agent = create_soc_agent(verbose=False)
        report = run_analysis(agent, alert_dict, verbose=False)

        # Also get the standalone ML prediction for structured data
        alert_json = json.dumps(alert_dict)
        prediction_raw = predict_anomaly.invoke({"alert_json": alert_json})
        prediction = _parse_prediction_result(prediction_raw, alert_dict)

        return {
            "report": report,
            "prediction": prediction,
        }
    except Exception as e:
        logger.exception("Investigation failed")
        raise HTTPException(status_code=500, detail=str(e))


# ── Helpers ────────────────────────────────────────────────────────

def _parse_prediction_result(raw: str, alert: dict) -> dict:
    """Parse the structured text from predict_anomaly into a JSON dict."""
    result = {
        "raw": raw,
        "prediction": "UNKNOWN",
        "confidence": 0.0,
        "attack_prob": 0.0,
        "normal_prob": 0.0,
        "top_features": [],
        "alert_summary": {
            "protocol_type": alert.get("protocol_type", "N/A"),
            "service": alert.get("service", "N/A"),
            "flag": alert.get("flag", "N/A"),
            "src_bytes": alert.get("src_bytes", 0),
            "dst_bytes": alert.get("dst_bytes", 0),
            "duration": alert.get("duration", 0),
        },
    }

    if raw.startswith("ERROR"):
        result["error"] = raw
        return result

    for line in raw.split("\n"):
        line = line.strip()
        if line.startswith("Prediction"):
            result["prediction"] = line.split(":")[-1].strip()
        elif line.startswith("Confidence"):
            try:
                result["confidence"] = float(line.split(":")[-1].strip().replace("%", ""))
            except ValueError:
                pass
        elif line.startswith("Attack Prob"):
            try:
                result["attack_prob"] = float(line.split(":")[-1].strip().replace("%", ""))
            except ValueError:
                pass
        elif line.startswith("Normal Prob"):
            try:
                result["normal_prob"] = float(line.split(":")[-1].strip().replace("%", ""))
            except ValueError:
                pass
        elif line.startswith("•") or line.startswith("\u2022"):
            # Parse feature importance lines
            parts = line.lstrip("•\u2022 ").strip()
            if "importance:" in parts:
                try:
                    name_val, imp = parts.rsplit("(importance:", 1)
                    name, val = name_val.split("=", 1)
                    result["top_features"].append({
                        "name": name.strip(),
                        "value": val.strip(),
                        "importance": float(imp.strip().rstrip(")")),
                    })
                except (ValueError, IndexError):
                    pass

    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
