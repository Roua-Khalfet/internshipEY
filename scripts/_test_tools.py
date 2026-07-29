"""Quick smoke test: verify tools work standalone before running the full agent."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from soc_agent.tools import predict_anomaly, search_nuclei_kb, get_nuclei_stats

print("=" * 60)
print("TEST 1: predict_anomaly (SYN Flood scenario)")
print("=" * 60)

alert = {
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "S0",
    "src_bytes": 0,
    "dst_bytes": 0,
    "wrong_fragment": 0,
    "hot": 0,
    "logged_in": 0,
    "num_compromised": 0,
    "count": 511,
    "srv_count": 511,
    "serror_rate": 1.0,
    "srv_serror_rate": 1.0,
    "rerror_rate": 0.0,
}

result = predict_anomaly.invoke({"alert_json": json.dumps(alert)})
print(result)

print("\n" + "=" * 60)
print("TEST 2: search_nuclei_kb (keyword: 'dos')")
print("=" * 60)

result2 = search_nuclei_kb.invoke({"query": "dos", "search_type": "tag"})
print(result2[:800])

print("\n" + "=" * 60)
print("TEST 3: get_nuclei_stats")
print("=" * 60)

result3 = get_nuclei_stats.invoke({})
print(result3[:500])

print("\n✅ All tools working!")
