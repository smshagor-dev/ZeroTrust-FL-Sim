"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";

type Round = {
  round_id: number;
  mean_client_loss: number;
  evaluation_loss: number | null;
  evaluation_accuracy: number | null;
  malicious_results: number;
  mitigation_score: number | null;
  attack_mitigated: boolean | null;
  round_duration_ms: number;
  selected_clients?: string[];
};

type Worker = {
  id: string;
  role: "Benign" | "Malicious";
  status: "Online" | "Offline";
  lastUpdate: string;
  latencyMs: number;
  dataSize: number;
};

type DashboardPayload = {
  mode: "live" | "preview";
  active: boolean;
  startedAt: number;
  elapsedSeconds: number;
  currentRound: number;
  totalRounds: number;
  attack: string;
  aggregator: string;
  device: string;
  benignWorkers: number;
  maliciousWorkers: number;
  rounds: Round[];
  workers: Worker[];
  logs: string[];
};

const NAV = [
  ["overview", "Overview", "home"],
  ["training", "Training", "training"],
  ["workers", "Workers", "workers"],
  ["security", "Security", "shield"],
  ["attacks", "Attacks", "warning"],
  ["metrics", "Metrics", "chart"],
  ["system", "System", "settings"],
  ["logs", "Logs", "logs"],
  ["settings", "Settings", "settings"],
] as const;

const DEMO: DashboardPayload = {
  mode: "preview",
  active: true,
  startedAt: Date.now() / 1000 - 1104,
  elapsedSeconds: 1104,
  currentRound: 12,
  totalRounds: 50,
  attack: "gaussian",
  aggregator: "median",
  device: "cpu",
  benignWorkers: 3,
  maliciousWorkers: 1,
  rounds: Array.from({ length: 12 }, (_, i) => ({
    round_id: i + 1,
    mean_client_loss: 1.7 * Math.exp(-i / 3.8) + 0.18,
    evaluation_loss: 1.35 * Math.exp(-i / 3.2) + 0.17,
    evaluation_accuracy: 0.18 + 0.74 * (1 - Math.exp(-i / 4.8)),
    malicious_results: 1,
    mitigation_score: 0.86 + i * 0.01,
    attack_mitigated: true,
    round_duration_ms: 12000 + ((i % 4) - 1) * 700,
  })),
  workers: [
    { id: "worker-1", role: "Benign", status: "Online", lastUpdate: "2s ago", latencyMs: 12, dataSize: 1024 },
    { id: "worker-2", role: "Benign", status: "Online", lastUpdate: "1s ago", latencyMs: 15, dataSize: 1024 },
    { id: "worker-3", role: "Benign", status: "Online", lastUpdate: "3s ago", latencyMs: 11, dataSize: 1024 },
    { id: "worker-4", role: "Malicious", status: "Online", lastUpdate: "2s ago", latencyMs: 14, dataSize: 1024 },
  ],
  logs: [
    "[12:18:20] [COORDINATOR] Global round 12 started...",
    "[12:18:21] [WORKER-1] Local training completed (loss: 0.2412)",
    "[12:18:21] [WORKER-2] Local training completed (loss: 0.2381)",
    "[12:18:22] [WORKER-3] Local training completed (loss: 0.2297)",
    "[12:18:22] [WORKER-4] Local training completed (loss: 2.3415) [MALICIOUS]",
    "[12:18:23] [CPP-AGGREGATOR] Applying Coordinate Median...",
    "[12:18:23] [SECURITY] Detected 1/4 malicious updates (97.8% mitigation)",
    "[12:18:24] [COORDINATOR] Global round 12 completed (accuracy: 92.34%)",
  ],
};

function Icon({ name, size = 22 }: { name: string; size?: number }) {
  const common = { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.9, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  const paths: Record<string, ReactNode> = {
    home: <><path d="M3 11 12 3l9 8"/><path d="M5 10v10h14V10"/><path d="M9 20v-6h6v6"/></>,
    training: <><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-7-7"/><path d="M5 12a7 7 0 0 0 7 7"/><path d="m16.5 4.8 2.7-.3-.3 2.7"/><path d="m7.5 19.2-2.7.3.3-2.7"/></>,
    workers: <><circle cx="8" cy="8" r="3"/><circle cx="17" cy="9" r="2.5"/><path d="M2.5 20c.4-4 2.6-6 5.5-6s5.1 2 5.5 6"/><path d="M13.5 15c3.2-.7 6.5.8 7.5 5"/></>,
    shield: <path d="M12 3 20 6v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6l8-3Z"/>,
    warning: <><path d="m12 3 9 17H3L12 3Z"/><path d="M12 9v5"/><path d="M12 17h.01"/></>,
    chart: <><path d="M4 19V5"/><path d="M4 19h16"/><path d="m7 15 4-4 3 2 5-6"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2H10V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"/></>,
    logs: <><path d="M5 4h14v16H5z"/><path d="M8 8h8M8 12h8M8 16h5"/></>,
    clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
    target: <><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/><path d="M17.5 6.5 21 3"/><path d="M17 3h4v4"/></>,
    loss: <><path d="M4 4v16h16"/><path d="m7 15 4-5 3 3 5-8"/></>,
    cpu: <><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></>,
    stop: <><circle cx="12" cy="12" r="8" fill="currentColor" stroke="none"/><rect x="9" y="9" width="6" height="6" rx="1" fill="#fff" stroke="none"/></>,
  };
  return <svg {...common}>{paths[name] ?? paths.chart}</svg>;
}

function ShieldLogo() {
  return <div className="brand-shield"><svg viewBox="0 0 52 58" aria-hidden><path d="M26 2 49 11v15c0 14.4-8.2 24.2-23 30C11.2 50.2 3 40.4 3 26V11L26 2Z" fill="#1988ed"/><path d="M26 8 43 14.7v11.2c0 10.8-5.7 18.7-17 23.7C14.7 44.6 9 36.7 9 25.9V14.7L26 8Z" fill="#0d56a3"/><path d="m26 15 4.1 7.3 8.2 1.5-5.8 5.9 1.1 8.3-7.6-3.6-7.6 3.6 1.1-8.3-5.8-5.9 8.2-1.5L26 15Z" fill="#061a2e"/></svg></div>;
}

function fmtDuration(seconds: number) {
  const h = Math.floor(seconds / 3600).toString().padStart(2, "0");
  const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, "0");
  const s = Math.floor(seconds % 60).toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function spark(points: number[], color: string) {
  const min = Math.min(...points), max = Math.max(...points), span = max - min || 1;
  const coords = points.map((p, i) => `${(i / Math.max(1, points.length - 1)) * 100},${32 - ((p - min) / span) * 26}`).join(" ");
  return <svg className="spark" viewBox="0 0 100 36" preserveAspectRatio="none"><polyline points={coords} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke"/></svg>;
}

function Kpi({ icon, title, value, trend, tone = "blue", sub, points }: { icon: string; title: string; value: string; trend?: string; tone?: "blue"|"green"; sub?: string; points?: number[] }) {
  const color = tone === "green" ? "#37e38f" : "#2b9cff";
  return <div className="card kpi-card">
    <div className="kpi-icon" style={{ color }}><Icon name={icon} size={30}/></div>
    <div className="kpi-copy"><div className="kpi-title">{title}</div><div className="kpi-value">{value}</div>{trend && <div className="kpi-trend" style={{ color }}>{trend}</div>}{sub && <div className="kpi-sub">{sub}</div>}</div>
    {points && <div className="spark-wrap">{spark(points, color)}</div>}
  </div>;
}

function pathFor(values: number[], width: number, height: number, padding = 8, minOverride?: number, maxOverride?: number) {
  if (!values.length) return "";
  const min = minOverride ?? Math.min(...values);
  const max = maxOverride ?? Math.max(...values);
  const span = max - min || 1;
  return values.map((v, i) => `${i ? "L" : "M"}${padding + (i / Math.max(1, values.length - 1)) * (width - padding * 2)},${height - padding - ((v - min) / span) * (height - padding * 2)}`).join(" ");
}

function ChartGrid({ children, yLabels = ["100", "80", "60", "40", "20", "0"] }: { children: ReactNode; yLabels?: string[] }) {
  return <div className="chart-canvas"><div className="y-labels">{yLabels.map(x => <span key={x}>{x}</span>)}</div><svg viewBox="0 0 560 210" preserveAspectRatio="none" className="chart-svg">
    {[0,1,2,3,4,5].map(i => <line key={`h${i}`} x1="36" x2="554" y1={14+i*36} y2={14+i*36} className="grid-line"/>)}
    {[0,1,2,3,4,5].map(i => <line key={`v${i}`} y1="12" y2="194" x1={36+i*103.6} x2={36+i*103.6} className="grid-line"/>)}
    {children}
  </svg><div className="x-axis">Round</div></div>;
}

function ConvergenceChart({ rounds }: { rounds: Round[] }) {
  const source = rounds.length ? rounds : DEMO.rounds;
  const train = source.map(r => Math.max(0.001, r.mean_client_loss));
  const test = source.map(r => Math.max(0.001, r.evaluation_loss ?? r.mean_client_loss * .9));
  const acc = source.map(r => Math.max(0, Math.min(1, r.evaluation_accuracy ?? 0)));
  const normalizeLog = (arr:number[]) => arr.map(v => Math.log10(v + .01));
  return <div className="card chart-card convergence"><div className="panel-title">Model Convergence</div><div className="legend"><span className="blue">Train Loss</span><span className="orange">Test Loss</span><span className="green">Test Accuracy</span></div><ChartGrid yLabels={["10¹","10⁰","10⁻¹","10⁻²"]}>
    <path d={pathFor(normalizeLog(train),560,210,36,-2,1)} className="line blue-line"/>
    <path d={pathFor(normalizeLog(test),560,210,36,-2,1)} className="line orange-line"/>
    <path d={pathFor(acc,560,210,36,0,1)} className="line green-line"/>
    {source.map((r,i)=><circle key={r.round_id} cx={36+(i/Math.max(1,source.length-1))*488} cy={174-acc[i]*138} r="3" className="dot-green"/>)}
  </ChartGrid></div>;
}

function AggregationChart({ rounds, workers }: { rounds: Round[]; workers: number }) {
  const source = rounds.length ? rounds : DEMO.rounds;
  return <div className="card chart-card"><div className="panel-title">Aggregation Metrics</div><div className="legend"><span className="green-box">Accepted Updates</span><span className="red-box">Rejected (Malicious)</span></div><ChartGrid>
    {source.slice(-12).map((r,i)=>{ const total = Math.max(1, r.selected_clients?.length ?? workers); const rejected=Math.min(total,r.malicious_results); const accepted=total-rejected; const x=52+i*40; const scale=31; return <g key={r.round_id}><rect x={x} y={194-accepted*scale} width="12" height={accepted*scale} rx="1" className="bar-green"/><rect x={x} y={194-(accepted+rejected)*scale} width="12" height={rejected*scale} rx="1" className="bar-red"/></g>; })}
  </ChartGrid></div>;
}

function ResourceChart({ rounds, device }: { rounds: Round[]; device: string }) {
  const n = Math.max(12, rounds.length || 0);
  const cpu = Array.from({length:n},(_,i)=>32+Math.min(28,i*2.1)+Math.sin(i*.9)*2);
  const gpu = Array.from({length:n},(_,i)=>device.toLowerCase().includes("cuda")?18+Math.min(42,i*2.8)+Math.sin(i*.7)*3:18+Math.sin(i*.8)*2);
  const mem = Array.from({length:n},(_,i)=>18+Math.min(9,i*.7)+Math.sin(i*.6)*1.5);
  return <div className="card chart-card resource-card"><div className="panel-heading"><div className="panel-title">Resource Usage</div><div className="tabs"><button className="active">CPU</button><button>GPU</button><button>Memory</button></div></div><ChartGrid>
    <path d={pathFor(cpu,560,210,36,0,100)} className="line blue-line"/><path d={pathFor(gpu,560,210,36,0,100)} className="line purple-line"/><path d={pathFor(mem,560,210,36,0,100)} className="line green-line"/>
  </ChartGrid></div>;
}

function Topology({ workers }: { workers: Worker[] }) {
  const list = workers.length >= 4 ? workers.slice(0,4) : DEMO.workers;
  return <div className="card topology-card"><div className="panel-title">Network Topology</div><div className="topology-stage"><svg className="topology-lines" viewBox="0 0 600 210" preserveAspectRatio="none"><line x1="300" y1="105" x2="90" y2="42"/><line x1="300" y1="105" x2="90" y2="168"/><line x1="300" y1="105" x2="510" y2="42"/><line x1="300" y1="105" x2="510" y2="168"/></svg>
    <div className="coordinator-node"><div className="hex"><Icon name="cpu" size={24}/></div><span>Coordinator</span></div>
    {list.map((w,i)=>{ const pos=["tl","bl","tr","br"][i]; return <div className={`worker-node ${pos}`} key={w.id}><div className={`node-dot ${w.role === "Malicious"?"bad":"good"}`}></div><span>{w.id}</span><small className={w.role === "Malicious"?"bad-text":"good-text"}>({w.role})</small></div>; })}
    <div className="topology-legend"><span><i className="legend-dot coord"></i>Coordinator</span><span><i className="legend-dot good"></i>Benign Worker</span><span><i className="legend-dot bad"></i>Malicious Worker</span></div>
  </div></div>;
}

function WorkerTable({ workers }: { workers: Worker[] }) {
  const list = workers.length ? workers : DEMO.workers;
  return <div className="card workers-card" id="workers"><div className="panel-title">Worker Status</div><div className="worker-table"><div className="worker-row worker-head"><span>ID</span><span>Role</span><span>Status</span><span>Last Update</span><span>Latency</span><span>Data Size</span><span></span></div>{list.map(w=><div className="worker-row" key={w.id}><span className="worker-id"><i className={`status-dot ${w.role==="Malicious"?"red":"green"}`}></i>{w.id}</span><span><b className={`pill ${w.role==="Malicious"?"danger":"benign"}`}>{w.role}</b></span><span><b className="pill online"><i></i>{w.status}</b></span><span>{w.lastUpdate}</span><span>{w.latencyMs} ms</span><span>{w.dataSize.toLocaleString("en-US")}</span><span className="kebab">⋮</span></div>)}</div></div>;
}

function Logs({ logs }: { logs: string[] }) {
  const list = logs.length ? logs.slice(-10) : DEMO.logs;
  return <div className="card logs-card" id="logs"><div className="panel-heading"><div className="panel-title">Live Logs</div><select defaultValue="all"><option value="all">All Components</option><option>Coordinator</option><option>Workers</option><option>Aggregator</option></select></div><pre className="log-window">{list.map((line,i)=><span key={`${i}-${line}`} className={line.includes("MALICIOUS")||line.includes("ATTACK")?"log-red":line.includes("SECURITY")?"log-yellow":line.includes("WORKER")?"log-green":line.includes("CPP")?"log-magenta":"log-blue"}>{line}{"\n"}</span>)}</pre></div>;
}

function Controls({ data }: { data: DashboardPayload }) {
  const [attack,setAttack]=useState(data.attack || "gaussian");
  const [agg,setAgg]=useState(data.aggregator || "median");
  const [notice,setNotice]=useState("");
  const save = () => { setNotice("Configuration staged for the next run"); setTimeout(()=>setNotice(""),2500); };
  return <div className="card controls-card" id="settings"><div className="control-title">Attack Configuration</div><div className="control-grid three"><label>Attack Type<select value={attack} onChange={e=>setAttack(e.target.value)}><option value="gaussian">Gaussian Noise</option><option value="label_flip">Label Flipping</option><option value="sign_flip">Sign Flip</option><option value="adaptive">Adaptive</option><option value="collusion">Collusion</option></select></label><label>Malicious Workers<input value={data.maliciousWorkers} readOnly/></label><label>Noise Scale (σ)<input defaultValue="1.0"/></label></div><div className="control-title training-title">Training Configuration</div><div className="control-grid three"><label>Total Rounds<input value={data.totalRounds} readOnly/></label><label>Local Epochs<select defaultValue="1"><option>1</option><option>2</option><option>5</option></select></label><label>Aggregator<select value={agg} onChange={e=>setAgg(e.target.value)}><option value="median">Coordinate Median</option><option value="trimmed_mean">Trimmed Mean</option><option value="krum">Krum</option><option value="multi_krum">Multi-Krum</option></select></label></div><div className="control-actions"><button className="primary" onClick={save}>⚙ Update Configuration</button><button className="danger-btn" onClick={()=>{setAttack("gaussian");setAgg("median")}}>↻ Reset to Default</button></div>{notice&&<div className="toast">{notice}</div>}</div>;
}

export default function Dashboard() {
  const [data,setData]=useState<DashboardPayload>(DEMO);
  const [activeNav,setActiveNav]=useState("overview");
  const [elapsed,setElapsed]=useState(DEMO.elapsedSeconds);
  const [stopping,setStopping]=useState(false);

  useEffect(()=>{
    let mounted=true;
    const load=async()=>{ try { const r=await fetch("/api/dashboard",{cache:"no-store"}); if(r.ok){const next=await r.json(); if(mounted)setData(next);} } catch{} };
    load(); const id=setInterval(load,1500); return()=>{mounted=false;clearInterval(id)};
  },[]);
  useEffect(()=>{ setElapsed(data.elapsedSeconds); const id=setInterval(()=>setElapsed(v=>data.active?v+1:v),1000); return()=>clearInterval(id); },[data.active,data.elapsedSeconds]);

  const rounds=data.rounds.length?data.rounds:DEMO.rounds;
  const last=rounds[rounds.length-1];
  const prev=rounds[Math.max(0,rounds.length-2)];
  const accuracy=(last?.evaluation_accuracy ?? .9234)*100;
  const loss=last?.evaluation_loss ?? .182;
  const accDelta=((last?.evaluation_accuracy ?? .9234)-(prev?.evaluation_accuracy ?? .9111))*100;
  const lossDelta=(last?.evaluation_loss ?? .182)-(prev?.evaluation_loss ?? .227);
  const mitigation=useMemo(()=>{ const vals=rounds.filter(r=>r.attack_mitigated!==null); return vals.length?vals.filter(r=>r.attack_mitigated).length/vals.length:.978; },[rounds]);
  const avgRound=rounds.reduce((s,r)=>s+r.round_duration_ms,0)/Math.max(1,rounds.length)/1000;
  const workerCount=data.benignWorkers+data.maliciousWorkers;
  const sparkAcc=rounds.map(r=>(r.evaluation_accuracy??0)*100), sparkLoss=rounds.map(r=>r.evaluation_loss??r.mean_client_loss), sparkTime=rounds.map(r=>r.round_duration_ms/1000);

  const stop=async()=>{ setStopping(true); try { await fetch("/api/dashboard",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({command:"stop"})}); } finally { setTimeout(()=>setStopping(false),1200); } };

  return <div className="dashboard-shell">
    <header className="topbar"><div className="brand"><ShieldLogo/><div><h1>ZeroTrust-FL-Sim</h1><p>Secure <i/> Private <i/> Resilient <i/> Scalable</p></div></div><div className="top-actions"><div className="status-chip"><span className={`pulse ${data.active?"on":""}`}></span>{data.active?"Training Active":"Training Idle"}</div><div className="header-chip">Round {data.currentRound || rounds.length} / {data.totalRounds}</div><div className="header-chip"><Icon name="clock" size={18}/>{fmtDuration(elapsed)}</div><button className="stop-button" onClick={stop} disabled={stopping}><Icon name="stop" size={17}/>{stopping?"Stopping…":"Stop Training"}</button></div></header>
    <aside className="sidebar"><nav>{NAV.map(([id,label,icon])=><button key={id} className={activeNav===id?"active":""} onClick={()=>setActiveNav(id)}><Icon name={icon} size={21}/><span>{label}</span></button>)}</nav><div className="sidebar-footer"><strong>ZeroTrust-FL-Sim</strong><span>v1.0.0</span><p>Built for Secure<br/>Federated Learning</p><div className="operational"><i></i>{data.mode === "live" ? "All Systems Operational" : "Preview Mode"}</div></div></aside>
    <main className="content">
      <section className="kpi-grid">
        <Kpi icon="target" title="Global Accuracy" value={`${accuracy.toFixed(2)}%`} trend={`↑ +${Math.max(0,accDelta).toFixed(2)}%`} points={sparkAcc}/>
        <Kpi icon="loss" title="Global Loss" value={loss.toFixed(3)} trend={`↓ ${lossDelta.toFixed(3)}`} tone="green" points={sparkLoss}/>
        <div className="card kpi-card active-workers"><div className="kpi-icon"><Icon name="workers" size={30}/></div><div className="kpi-copy"><div className="kpi-title">Active Workers</div><div className="kpi-value">{workerCount} / {workerCount}</div><div className="kpi-sub">{data.benignWorkers} benign, {data.maliciousWorkers} malicious</div></div><div className="worker-progress"><div style={{width:`${workerCount?data.benignWorkers/workerCount*100:0}%`}}></div></div></div>
        <Kpi icon="shield" title="Mitigation Rate" value={`${(mitigation*100).toFixed(1)}%`} trend="↑ +0.5%" tone="green" points={rounds.map(r=>(r.mitigation_score??mitigation)*100)}/>
        <Kpi icon="clock" title="Avg. Round Time" value={`${avgRound.toFixed(1)}s`} trend="↓ -2.1s" points={sparkTime}/>
      </section>
      <section className="charts-grid" id="metrics"><ConvergenceChart rounds={rounds}/><AggregationChart rounds={rounds} workers={workerCount}/><ResourceChart rounds={rounds} device={data.device}/></section>
      <section className="middle-grid"><WorkerTable workers={data.workers}/><Topology workers={data.workers}/></section>
      <section className="bottom-grid"><Logs logs={data.logs}/><Controls data={data}/></section>
    </main>
  </div>;
}
