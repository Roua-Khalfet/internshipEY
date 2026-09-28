# SOC Copilot — AI-Powered Security Operations Center

## Purpose

An AI-powered SOC assistant that combines **XGBoost intrusion detection** (trained on NSL-KDD) with a **Nuclei vulnerability knowledge base** (13k+ templates). A LangChain/LangGraph **ReAct agent** correlates ML predictions with known CVEs to produce human-readable incident reports.

## Architecture

```
┌────────────────────┐     REST API      ┌──────────────────────┐
│   Next.js Frontend │  ──────────────►  │   FastAPI Backend    │
│   (frontend/)      │   localhost:8000   │   (backend/main.py)  │
└────────────────────┘                   └──────┬───────────────┘
                                                │  imports
                                    ┌───────────▼────────────┐
                                    │     soc_agent/          │
                                    │  LangGraph ReAct Agent  │
                                    │  (NVIDIA, Gemini, Groq) │
                                    └───┬──────────┬──────────┘
                            ┌───────────▼──┐  ┌───▼─────────────┐
                            │ XGBoost .pkl │  │ nuclei_kb.db     │
                            │ ML Pipeline  │  │ SQLite (13k CVE) │
                            └──────────────┘  └─────────────────┘
                                                      ▲
                                    ┌─────────────────┘
                                    │  built by
                              ┌─────▼──────────────┐
                              │ nuclei_kb/ package  │
                              │ sync → parse → DB   │
                              └────────────────────┘
```

## Components

| Component | Path | Description |
|-----------|------|-------------|
| **SOC Agent** | `soc_agent/` | LangChain tools + LangGraph ReAct agent (ML predict, Nuclei KB search, stats) |
| **Backend API** | `backend/main.py` | FastAPI REST: `/api/health`, `/api/predict`, `/api/search-nuclei`, `/api/nuclei-stats`, `/api/investigate` |
| **Frontend** | `frontend/` | Next.js dashboard with scenario selector, ML results display, investigation UI |
| **Nuclei KB** | `nuclei_kb/` | Git sync + YAML parsing + SQLite pipeline for Nuclei vulnerability templates |
| **ML Model** | `nsl_kdd_xgboost_pipeline.pkl` | scikit-learn Pipeline (OrdinalEncoder + StandardScaler + XGBoost) on NSL-KDD |
| **Retrain** | `retrain_model.py` | Re-trains XGBoost pipeline from `KDDTrain+.txt` |
| **Streamlit** | `nuclei_kb/dashboard.py` | Nuclei KB stats dashboard (KPIs, severity/protocol charts, top tags) |
| **CI/CD** | `.github/workflows/sync_nuclei.yml` | Daily GitHub Actions: sync templates → parse → report |

## How to Run

### 1. Backend API
```bash
cd backend
..\venv\Scripts\activate     # Windows
uvicorn main:app --reload --port 8000
```

### 2. Frontend
```bash
cd frontend
npm install                   # first time only
npm run dev                   # http://localhost:3000
```

### 3. Nuclei KB Pipeline (build/update the SQLite DB)
```bash
python scripts/run_pipeline.py          # incremental sync
python scripts/run_pipeline.py --full   # full re-scan
```

### 4. SOC Copilot Demo (CLI, needs LLM API key in .env)
```bash
python scripts/run_soc_copilot.py --scenario 1   # SYN Flood test
```

### 5. Streamlit Dashboard
```bash
streamlit run nuclei_kb/dashboard.py
```

### 6. Retrain ML Model
```bash
# Back up existing model first!
python retrain_model.py       # requires KDDTrain+.txt
```

## Environment Variables (.env)

| Variable | Required | Description |
|----------|----------|-------------|
| `LLM_PROVIDER` | No | Provider: `nvidia` (default if key set), `gemini`, or `groq` |
| `NVIDIA_API_KEY` | Yes (for NVIDIA) | NVIDIA API key (NIM / OpenAI-compatible endpoint) |
| `NVIDIA_BASE_URL` | No | Base URL (default: `https://integrate.api.nvidia.com/v1`) |
| `SOC_LLM_MODEL` | No | LLM model name (default: `moonshotai/kimi-k3` for nvidia, `gemini-3.8-flash` for gemini) |
| `GEMINI_API_KEY` | Optional | Google Gemini API key |
| `GROQ_API_KEY` | Optional | Groq API key |

## Key Dependencies

- **Python**: langchain, langgraph, langchain-openai, langchain-google-genai, langchain-groq, xgboost, scikit-learn, fastapi, uvicorn, streamlit, pandas, PyYAML
- **Node.js**: Next.js 16, React, Tailwind CSS

