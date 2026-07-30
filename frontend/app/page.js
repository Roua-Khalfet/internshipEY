"use client";
import { useState, useEffect } from "react";

const API = "http://localhost:8000";

// ── Pre-filled attack scenarios ───────────────────────────────────
const SCENARIOS = {
  syn_flood: {
    name: "SYN Flood (Neptune)",
    icon: "🔴",
    alert: {
      protocol_type:"tcp",service:"ftp_data",flag:"S0",duration:0,src_bytes:0,dst_bytes:0,
      land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:0,
      num_compromised:0,root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,
      num_shells:0,num_access_files:0,num_outbound_cmds:0,is_host_login:0,is_guest_login:0,
      count:50,srv_count:11,serror_rate:1.0,srv_serror_rate:1.0,rerror_rate:0.0,
      srv_rerror_rate:0.0,same_srv_rate:0.22,diff_srv_rate:0.08,srv_diff_host_rate:0.0,
      dst_host_count:255,dst_host_srv_count:63,dst_host_same_srv_rate:0.25,
      dst_host_diff_srv_rate:0.02,dst_host_same_src_port_rate:0.01,
      dst_host_srv_diff_host_rate:0.0,dst_host_serror_rate:1.0,dst_host_srv_serror_rate:1.0,
      dst_host_rerror_rate:0.0,dst_host_srv_rerror_rate:0.0
    },
  },
  ftp_exfil: {
    name: "FTP Exfil (Warez)",
    icon: "🟠",
    alert: {
      protocol_type:"tcp",service:"ftp_data",flag:"SF",duration:0,src_bytes:334,
      dst_bytes:0,land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:1,
      num_compromised:0,root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,
      num_shells:0,num_access_files:0,num_outbound_cmds:0,is_host_login:0,is_guest_login:0,
      count:2,srv_count:2,serror_rate:0.0,srv_serror_rate:0.0,rerror_rate:0.0,
      srv_rerror_rate:0.0,same_srv_rate:1.0,diff_srv_rate:0.0,srv_diff_host_rate:0.0,
      dst_host_count:2,dst_host_srv_count:20,dst_host_same_srv_rate:1.0,
      dst_host_diff_srv_rate:0.0,dst_host_same_src_port_rate:1.0,
      dst_host_srv_diff_host_rate:0.2,dst_host_serror_rate:0.0,dst_host_srv_serror_rate:0.0,
      dst_host_rerror_rate:0.0,dst_host_srv_rerror_rate:0.0
    },
  },
  dns_tunnel: {
    name: "IP Sweep (Recon)",
    icon: "🟡",
    alert: {
      protocol_type:"icmp",service:"eco_i",flag:"SF",duration:0,src_bytes:18,
      dst_bytes:0,land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:0,
      num_compromised:0,root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,
      num_shells:0,num_access_files:0,num_outbound_cmds:0,is_host_login:0,is_guest_login:0,
      count:1,srv_count:1,serror_rate:0.0,srv_serror_rate:0.0,rerror_rate:0.0,
      srv_rerror_rate:0.0,same_srv_rate:1.0,diff_srv_rate:0.0,srv_diff_host_rate:0.0,
      dst_host_count:1,dst_host_srv_count:16,dst_host_same_srv_rate:1.0,
      dst_host_diff_srv_rate:0.0,dst_host_same_src_port_rate:1.0,
      dst_host_srv_diff_host_rate:1.0,dst_host_serror_rate:0.0,dst_host_srv_serror_rate:0.0,
      dst_host_rerror_rate:0.0,dst_host_srv_rerror_rate:0.0
    },
  },
  normal_traffic: {
    name: "Normal Traffic",
    icon: "🟢",
    alert: {
      protocol_type:"tcp",service:"http",flag:"SF",duration:5,src_bytes:230,
      dst_bytes:8150,land:0,wrong_fragment:0,urgent:0,hot:0,num_failed_logins:0,logged_in:1,
      num_compromised:0,root_shell:0,su_attempted:0,num_root:0,num_file_creations:0,
      num_shells:0,num_access_files:0,num_outbound_cmds:0,is_host_login:0,is_guest_login:0,
      count:5,srv_count:5,serror_rate:0.0,srv_serror_rate:0.0,rerror_rate:0.0,
      srv_rerror_rate:0.0,same_srv_rate:1.0,diff_srv_rate:0.0,srv_diff_host_rate:0.0,
      dst_host_count:30,dst_host_srv_count:255,dst_host_same_srv_rate:1.0,
      dst_host_diff_srv_rate:0.0,dst_host_same_src_port_rate:0.04,
      dst_host_srv_diff_host_rate:0.0,dst_host_serror_rate:0.0,dst_host_srv_serror_rate:0.0,
      dst_host_rerror_rate:0.0,dst_host_srv_rerror_rate:0.0,
    },
  },
};

const FEATURE_GROUPS = {
  "Connection": ["protocol_type","service","flag","duration","src_bytes","dst_bytes","land","wrong_fragment","urgent"],
  "Content": ["hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login"],
  "Traffic": ["count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate"],
  "Host": ["dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate"],
};

const CATEGORICAL = ["protocol_type","service","flag"];

const DEFAULT_ALERT = SCENARIOS.syn_flood.alert;

export default function Home() {
  const [tab, setTab] = useState("investigate");
  const [alert, setAlert] = useState({...DEFAULT_ALERT});
  const [prediction, setPrediction] = useState(null);
  const [report, setReport] = useState("");
  const [loading, setLoading] = useState(false);
  const [loadingType, setLoadingType] = useState("");
  const [stats, setStats] = useState(null);
  const [nucleiQuery, setNucleiQuery] = useState("");
  const [nucleiType, setNucleiType] = useState("keyword");
  const [nucleiResults, setNucleiResults] = useState("");
  const [nucleiLoading, setNucleiLoading] = useState(false);
  const [activeScenario, setActiveScenario] = useState("syn_flood");
  const [expandedGroup, setExpandedGroup] = useState("Connection");

  useEffect(() => {
    fetch(`${API}/api/nuclei-stats`)
      .then(r => r.json())
      .then(d => setStats(d.raw))
      .catch(() => {});
  }, []);

  const updateFeature = (key, val) => {
    setAlert(prev => ({
      ...prev,
      [key]: CATEGORICAL.includes(key) ? val : (val === "" ? 0 : parseFloat(val) || 0),
    }));
  };

  const loadScenario = (key) => {
    setActiveScenario(key);
    setAlert({...SCENARIOS[key].alert});
    setPrediction(null);
    setReport("");
  };

  const runPredict = async () => {
    setLoading(true); setLoadingType("predict"); setPrediction(null); setReport("");
    try {
      const res = await fetch(`${API}/api/predict`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(alert),
      });
      const data = await res.json();
      setPrediction(data);
    } catch(e) { setPrediction({error: e.message}); }
    setLoading(false); setLoadingType("");
  };

  const runInvestigate = async () => {
    setLoading(true); setLoadingType("investigate"); setPrediction(null); setReport("");
    try {
      const res = await fetch(`${API}/api/investigate`, {
        method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({alert}),
      });
      const data = await res.json();
      setPrediction(data.prediction);
      setReport(data.report);
    } catch(e) { setReport("Error: " + e.message); }
    setLoading(false); setLoadingType("");
  };

  const searchNuclei = async () => {
    if(!nucleiQuery.trim()) return;
    setNucleiLoading(true); setNucleiResults("");
    try {
      const res = await fetch(`${API}/api/search-nuclei?query=${encodeURIComponent(nucleiQuery)}&search_type=${nucleiType}`);
      const data = await res.json();
      setNucleiResults(data.raw);
    } catch(e) { setNucleiResults("Error: " + e.message); }
    setNucleiLoading(false);
  };

  return (
    <div style={{minHeight:"100vh", background:"var(--bg-primary)"}}>
      {/* Header */}
      <header style={{
        background:"linear-gradient(135deg, rgba(6,182,212,0.08) 0%, rgba(16,185,129,0.05) 100%)",
        borderBottom:"1px solid var(--border-color)", padding:"1.25rem 2rem",
        display:"flex", alignItems:"center", justifyContent:"space-between",
      }}>
        <div style={{display:"flex",alignItems:"center",gap:"0.75rem"}}>
          <div style={{
            width:42,height:42,borderRadius:12,
            background:"linear-gradient(135deg,var(--accent-cyan),var(--accent-emerald))",
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:"1.3rem",
          }}>🛡️</div>
          <div>
            <h1 style={{margin:0,fontSize:"1.3rem",fontWeight:800,letterSpacing:"-0.02em",
              background:"linear-gradient(135deg,var(--accent-cyan),var(--accent-emerald))",
              WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",
            }}>SOC COPILOT</h1>
            <p style={{margin:0,fontSize:"0.75rem",color:"var(--text-secondary)"}}>
              AI-Powered Intrusion Detection &amp; Threat Intelligence
            </p>
          </div>
        </div>
        <div style={{display:"flex",gap:"0.5rem"}}>
          {[
            {key:"investigate",label:"🔍 Investigate",},
            {key:"nuclei",label:"📚 Nuclei KB"},
          ].map(t => (
            <button key={t.key} className={`btn-secondary ${tab===t.key?"active":""}`}
              onClick={() => setTab(t.key)}>{t.label}</button>
          ))}
        </div>
      </header>

      <main style={{maxWidth:1400,margin:"0 auto",padding:"1.5rem 2rem"}}>

        {/* ── INVESTIGATE TAB ────────────────────────────── */}
        {tab === "investigate" && (
          <div className="animate-fade-in">
            {/* Stats Cards */}
            {stats && (
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(180px,1fr))",gap:"1rem",marginBottom:"1.5rem"}}>
                {parseStats(stats).map((s,i) => (
                  <div key={i} className="stat-card" style={{textAlign:"center"}}>
                    <div style={{fontSize:"1.8rem",fontWeight:800,color:s.color}}>{s.value}</div>
                    <div style={{fontSize:"0.75rem",color:"var(--text-secondary)",marginTop:"0.25rem"}}>{s.label}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Scenario Buttons */}
            <div style={{marginBottom:"1.25rem"}}>
              <div style={{fontSize:"0.8rem",color:"var(--text-secondary)",marginBottom:"0.5rem",fontWeight:600,textTransform:"uppercase",letterSpacing:"0.05em"}}>
                Quick-Load Scenarios
              </div>
              <div style={{display:"flex",gap:"0.5rem",flexWrap:"wrap"}}>
                {Object.entries(SCENARIOS).map(([key,s]) => (
                  <button key={key} className={`btn-secondary ${activeScenario===key?"active":""}`}
                    onClick={() => loadScenario(key)}>
                    {s.icon} {s.name}
                  </button>
                ))}
              </div>
            </div>

            <div style={{display:"grid",gridTemplateColumns:"minmax(0,1fr) minmax(0,1.2fr)",gap:"1.5rem"}}>
              {/* Left: Feature Form */}
              <div className="glass-card" style={{padding:"1.25rem",maxHeight:"75vh",overflowY:"auto"}}>
                <h3 style={{margin:"0 0 1rem",fontSize:"1rem",fontWeight:700,color:"var(--accent-cyan)"}}>
                  Network Flow Features
                </h3>
                {Object.entries(FEATURE_GROUPS).map(([group, features]) => (
                  <div key={group} style={{marginBottom:"0.75rem"}}>
                    <button onClick={() => setExpandedGroup(expandedGroup===group?null:group)}
                      style={{
                        width:"100%",textAlign:"left",background:"var(--bg-secondary)",
                        border:"1px solid var(--border-color)",borderRadius:10,padding:"0.6rem 0.85rem",
                        color:"var(--text-primary)",cursor:"pointer",fontWeight:600,fontSize:"0.85rem",
                        display:"flex",justifyContent:"space-between",alignItems:"center",
                      }}>
                      <span>{group}</span>
                      <span style={{fontSize:"0.75rem",color:"var(--text-secondary)"}}>
                        {features.length} features {expandedGroup===group?"▼":"▶"}
                      </span>
                    </button>
                    {expandedGroup===group && (
                      <div style={{
                        display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:"0.5rem",
                        padding:"0.75rem 0.5rem",animation:"fadeIn 0.3s ease-out",
                      }}>
                        {features.map(f => (
                          <div key={f}>
                            <label style={{display:"block",marginBottom:"0.2rem"}}>{f.replace(/_/g," ")}</label>
                            {CATEGORICAL.includes(f) ? (
                              <input type="text" value={alert[f]||""} onChange={e => updateFeature(f, e.target.value)} />
                            ) : (
                              <input type="number" step="any" value={alert[f]??0} onChange={e => updateFeature(f, e.target.value)} />
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}

                <div style={{display:"flex",gap:"0.75rem",marginTop:"1rem"}}>
                  <button className="btn-primary" onClick={runPredict}
                    disabled={loading} style={{flex:1}}>
                    {loading && loadingType==="predict" ? <><span className="loading-spinner" /> Running ML...</> : "⚡ ML Predict Only"}
                  </button>
                  <button className="btn-primary" onClick={runInvestigate}
                    disabled={loading}
                    style={{flex:1,background:"linear-gradient(135deg,var(--accent-purple),var(--accent-cyan))"}}>
                    {loading && loadingType==="investigate" ? <><span className="loading-spinner" /> Investigating...</> : "🤖 Full AI Investigation"}
                  </button>
                </div>
              </div>

              {/* Right: Results */}
              <div style={{display:"flex",flexDirection:"column",gap:"1rem"}}>
                {/* Prediction Card */}
                {prediction && !prediction.error && (
                  <div className="glass-card animate-fade-in" style={{padding:"1.25rem"}}>
                    <h3 style={{margin:"0 0 1rem",fontSize:"1rem",fontWeight:700,color:"var(--accent-cyan)"}}>
                      ML Prediction Result
                    </h3>
                    <div style={{display:"flex",gap:"1rem",marginBottom:"1rem"}}>
                      <div style={{
                        flex:1,textAlign:"center",padding:"1rem",borderRadius:12,
                        background: prediction.prediction==="ATTACK"
                          ? "rgba(239,68,68,0.1)" : "rgba(16,185,129,0.1)",
                        border: `1px solid ${prediction.prediction==="ATTACK"
                          ? "rgba(239,68,68,0.3)" : "rgba(16,185,129,0.3)"}`,
                      }}>
                        <div style={{fontSize:"2rem",fontWeight:900,
                          color: prediction.prediction==="ATTACK" ? "var(--accent-red)" : "var(--accent-emerald)",
                        }}>{prediction.prediction}</div>
                        <div style={{fontSize:"0.8rem",color:"var(--text-secondary)"}}>Prediction</div>
                      </div>
                      <div style={{flex:1,textAlign:"center",padding:"1rem",borderRadius:12,background:"var(--bg-secondary)",border:"1px solid var(--border-color)"}}>
                        <div style={{fontSize:"2rem",fontWeight:900,color:"var(--accent-cyan)"}}>{prediction.confidence?.toFixed(1)}%</div>
                        <div style={{fontSize:"0.8rem",color:"var(--text-secondary)"}}>Confidence</div>
                      </div>
                    </div>
                    {/* Probability bars */}
                    <div style={{marginBottom:"1rem"}}>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:"0.3rem"}}>
                        <span style={{fontSize:"0.8rem",color:"var(--accent-red)"}}>Attack</span>
                        <span style={{fontSize:"0.8rem",color:"var(--text-secondary)"}}>{prediction.attack_prob?.toFixed(1)}%</span>
                      </div>
                      <div style={{height:8,borderRadius:4,background:"var(--bg-secondary)",overflow:"hidden"}}>
                        <div style={{height:"100%",width:`${prediction.attack_prob||0}%`,borderRadius:4,
                          background:"linear-gradient(90deg,var(--accent-red),#f97316)",transition:"width 0.5s ease"}} />
                      </div>
                    </div>
                    <div>
                      <div style={{display:"flex",justifyContent:"space-between",marginBottom:"0.3rem"}}>
                        <span style={{fontSize:"0.8rem",color:"var(--accent-emerald)"}}>Normal</span>
                        <span style={{fontSize:"0.8rem",color:"var(--text-secondary)"}}>{prediction.normal_prob?.toFixed(1)}%</span>
                      </div>
                      <div style={{height:8,borderRadius:4,background:"var(--bg-secondary)",overflow:"hidden"}}>
                        <div style={{height:"100%",width:`${prediction.normal_prob||0}%`,borderRadius:4,
                          background:"linear-gradient(90deg,var(--accent-emerald),var(--accent-cyan))",transition:"width 0.5s ease"}} />
                      </div>
                    </div>
                    {/* Top features */}
                    {prediction.top_features?.length > 0 && (
                      <div style={{marginTop:"1rem"}}>
                        <div style={{fontSize:"0.8rem",fontWeight:600,color:"var(--text-secondary)",marginBottom:"0.5rem",textTransform:"uppercase",letterSpacing:"0.05em"}}>
                          Top Contributing Features
                        </div>
                        {prediction.top_features.map((f,i) => (
                          <div key={i} style={{display:"flex",alignItems:"center",gap:"0.5rem",marginBottom:"0.4rem"}}>
                            <div style={{width:120,fontSize:"0.8rem",color:"var(--accent-cyan)",fontFamily:"'JetBrains Mono',monospace"}}>{f.name}</div>
                            <div style={{flex:1,height:6,borderRadius:3,background:"var(--bg-secondary)",overflow:"hidden"}}>
                              <div style={{height:"100%",width:`${(f.importance*100/0.15).toFixed(0)}%`,maxWidth:"100%",borderRadius:3,
                                background:"linear-gradient(90deg,var(--accent-cyan),var(--accent-purple))",transition:"width 0.5s ease"}} />
                            </div>
                            <div style={{fontSize:"0.75rem",color:"var(--text-secondary)",width:50,textAlign:"right"}}>
                              {(f.importance*100).toFixed(1)}%
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {prediction?.error && (
                  <div className="glass-card animate-fade-in" style={{padding:"1.25rem",borderColor:"rgba(239,68,68,0.3)"}}>
                    <h3 style={{color:"var(--accent-red)",margin:"0 0 0.5rem"}}>Error</h3>
                    <p style={{color:"var(--text-secondary)",margin:0,fontSize:"0.9rem"}}>{prediction.error}</p>
                  </div>
                )}

                {/* LLM Report */}
                {report && (
                  <div className="glass-card animate-fade-in" style={{padding:"1.25rem",maxHeight:"50vh",overflowY:"auto"}}>
                    <h3 style={{margin:"0 0 1rem",fontSize:"1rem",fontWeight:700,color:"var(--accent-purple)"}}>
                      🤖 AI Investigation Report
                    </h3>
                    <div className="markdown-report"
                      dangerouslySetInnerHTML={{__html: simpleMarkdown(report)}} />
                  </div>
                )}

                {/* Empty state */}
                {!prediction && !report && !loading && (
                  <div className="glass-card" style={{padding:"3rem",textAlign:"center"}}>
                    <div style={{fontSize:"3rem",marginBottom:"1rem"}}>🔍</div>
                    <h3 style={{color:"var(--text-primary)",margin:"0 0 0.5rem"}}>Ready to Investigate</h3>
                    <p style={{color:"var(--text-secondary)",margin:0,fontSize:"0.9rem"}}>
                      Select a scenario or fill in network features, then click Predict or Investigate.
                    </p>
                  </div>
                )}

                {loading && (
                  <div className="glass-card animate-fade-in" style={{padding:"3rem",textAlign:"center"}}>
                    <div className="loading-spinner" style={{width:40,height:40,borderWidth:3,marginBottom:"1rem"}} />
                    <h3 style={{color:"var(--accent-cyan)",margin:"0 0 0.5rem"}}>
                      {loadingType==="investigate" ? "AI Agent Investigating..." : "Running ML Prediction..."}
                    </h3>
                    <p style={{color:"var(--text-secondary)",margin:0,fontSize:"0.85rem"}}>
                      {loadingType==="investigate"
                        ? "The LLM agent is analyzing features, searching the Nuclei KB, and writing the report..."
                        : "Running XGBoost pipeline on your network flow features..."}
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ── NUCLEI KB TAB ──────────────────────────────── */}
        {tab === "nuclei" && (
          <div className="animate-fade-in">
            <div className="glass-card" style={{padding:"1.25rem",marginBottom:"1.5rem"}}>
              <h3 style={{margin:"0 0 1rem",fontSize:"1.1rem",fontWeight:700,color:"var(--accent-cyan)"}}>
                📚 Nuclei Vulnerability Knowledge Base
              </h3>
              <div style={{display:"flex",gap:"0.75rem",alignItems:"flex-end"}}>
                <div style={{flex:1}}>
                  <label style={{display:"block",marginBottom:"0.3rem"}}>Search Query</label>
                  <input type="text" value={nucleiQuery} onChange={e => setNucleiQuery(e.target.value)}
                    placeholder="e.g. rce, CVE-2022-22965, spring, sqli..."
                    onKeyDown={e => e.key==="Enter" && searchNuclei()} />
                </div>
                <div style={{width:160}}>
                  <label style={{display:"block",marginBottom:"0.3rem"}}>Search Type</label>
                  <select value={nucleiType} onChange={e => setNucleiType(e.target.value)}>
                    <option value="keyword">Keyword</option>
                    <option value="tag">Tag</option>
                    <option value="protocol">Protocol</option>
                    <option value="severity">Severity</option>
                  </select>
                </div>
                <button className="btn-primary" onClick={searchNuclei} disabled={nucleiLoading}
                  style={{height:42,whiteSpace:"nowrap"}}>
                  {nucleiLoading ? <span className="loading-spinner" /> : "Search"}
                </button>
              </div>
            </div>

            {nucleiResults && (
              <div className="glass-card animate-fade-in" style={{padding:"1.25rem"}}>
                <pre style={{
                  margin:0,whiteSpace:"pre-wrap",fontFamily:"'JetBrains Mono',monospace",
                  fontSize:"0.82rem",lineHeight:1.7,color:"var(--text-secondary)",
                }}>{nucleiResults}</pre>
              </div>
            )}

            {stats && (
              <div className="glass-card" style={{padding:"1.25rem",marginTop:"1.5rem"}}>
                <h3 style={{margin:"0 0 1rem",fontSize:"1rem",fontWeight:700,color:"var(--accent-emerald)"}}>
                  📊 Knowledge Base Statistics
                </h3>
                <pre style={{
                  margin:0,whiteSpace:"pre-wrap",fontFamily:"'JetBrains Mono',monospace",
                  fontSize:"0.82rem",lineHeight:1.7,color:"var(--text-secondary)",
                }}>{stats}</pre>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────

function parseStats(raw) {
  const stats = [];
  const totalMatch = raw.match(/Total Templates\s*:\s*([\d,]+)/);
  if (totalMatch) stats.push({ label: "Total Templates", value: totalMatch[1], color: "var(--accent-cyan)" });
  
  const critMatch = raw.match(/critical\s*:\s*([\d,]+)/);
  if (critMatch) stats.push({ label: "Critical", value: critMatch[1], color: "#ef4444" });

  const highMatch = raw.match(/high\s*:\s*([\d,]+)/);
  if (highMatch) stats.push({ label: "High", value: highMatch[1], color: "#f97316" });

  const medMatch = raw.match(/medium\s*:\s*([\d,]+)/);
  if (medMatch) stats.push({ label: "Medium", value: medMatch[1], color: "#f59e0b" });

  const lowMatch = raw.match(/low\s*:\s*([\d,]+)/);
  if (lowMatch) stats.push({ label: "Low", value: lowMatch[1], color: "#3b82f6" });

  const infoMatch = raw.match(/info\s*:\s*([\d,]+)/);
  if (infoMatch) stats.push({ label: "Info", value: infoMatch[1], color: "#6b7280" });

  return stats;
}

function simpleMarkdown(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h2>$1</h2>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^---$/gm, '<hr/>')
    .replace(/^- (.+)$/gm, '<li>$1</li>')
    .replace(/^(\d+)\. (.+)$/gm, '<li><strong>$1.</strong> $2</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br/>')
    .replace(/^/, '<p>').replace(/$/, '</p>');
}
