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
  completed_clients?: string[];
  failed_clients?: string[];
  straggler_clients?: string[];
};

type Worker = {
  id: string;
  role: "Benign" | "Malicious";
  status: "Online" | "Offline";
  lastUpdateAt: number | null;
  latencyMs: number | null;
  dataSize: number;
  trainingDurationMs: number | null;
  loss: number | null;
  lastRound: number | null;
};

type SystemSample = {
  timestamp: number;
  cpuPercent: number;
  memoryPercent: number;
  gpuMemoryPercent: number | null;
};

type DashboardPayload = {
  available: boolean;
  active: boolean;
  startedAt: number | null;
  updatedAt: number | null;
  elapsedSeconds: number;
  currentRound: number | null;
  totalRounds: number | null;
  attack: string | null;
  aggregator: string | null;
  device: string | null;
  benignWorkers: number;
  maliciousWorkers: number;
  rounds: Round[];
  workers: Worker[];
  systemSamples: SystemSample[];
  logs: string[];
};

const EMPTY: DashboardPayload = {
  available: false,
  active: false,
  startedAt: null,
  updatedAt: null,
  elapsedSeconds: 0,
  currentRound: null,
  totalRounds: null,
  attack: null,
  aggregator: null,
  device: null,
  benignWorkers: 0,
  maliciousWorkers: 0,
  rounds: [],
  workers: [],
  systemSamples: [],
  logs: [],
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

function Icon({ name, size = 22 }: { name: string; size?: number }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.9,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
  };
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

function formatAge(timestamp: number | null) {
  if (timestamp === null) return "—";
  const age = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (age < 2) return "just now";
  if (age < 60) return `${age}s ago`;
  const minutes = Math.floor(age / 60);
  return `${minutes}m ago`;
}

function coord(value: number) {
  return Number(value.toFixed(3));
}

function spark(points: number[], color: string) {
  if (!points.length) return null;
  const min = Math.min(...points);
  const max = Math.max(...points);
  const span = max - min || 1;
  const coords = points
    .map((point, index) => `${coord((index / Math.max(1, points.length - 1)) * 100)},${coord(32 - ((point - min) / span) * 26)}`)
    .join(" ");
  return <svg className="spark" viewBox="0 0 100 36" preserveAspectRatio="none"><polyline points={coords} fill="none" stroke={color} strokeWidth="2" vectorEffect="non-scaling-stroke"/></svg>;
}

function Kpi({ icon, title, value, trend, tone = "blue", sub, points }: { icon: string; title: string; value: string; trend?: string; tone?: "blue" | "green"; sub?: string; points?: number[] }) {
  const color = tone === "green" ? "#37e38f" : "#2b9cff";
  return <div className="card kpi-card">
    <div className="kpi-icon" style={{ color }}><Icon name={icon} size={30}/></div>
    <div className="kpi-copy"><div className="kpi-title">{title}</div><div className="kpi-value">{value}</div>{trend && <div className="kpi-trend" style={{ color }}>{trend}</div>}{sub && <div className="kpi-sub">{sub}</div>}</div>
    {points && points.length > 0 && <div className="spark-wrap">{spark(points, color)}</div>}
  </div>;
}

function pathFor(values: number[], width: number, height: number, padding = 8, minOverride?: number, maxOverride?: number) {
  if (!values.length) return "";
  const min = minOverride ?? Math.min(...values);
  const max = maxOverride ?? Math.max(...values);
  const span = max - min || 1;
  return values.map((value, index) => `${index ? "L" : "M"}${coord(padding + (index / Math.max(1, values.length - 1)) * (width - padding * 2))},${coord(height - padding - ((value - min) / span) * (height - padding * 2))}`).join(" ");
}

function EmptyData({ text }: { text: string }) {
  return <div className="data-empty" style={{ padding: "32px 8px", textAlign: "center", opacity: 0.7 }}>{text}</div>;
}

function ChartGrid({ children, yLabels = ["100", "80", "60", "40", "20", "0"], xLabel = "Round" }: { children: ReactNode; yLabels?: string[]; xLabel?: string }) {
  return <div className="chart-canvas"><div className="y-labels">{yLabels.map((label) => <span key={label}>{label}</span>)}</div><svg viewBox="0 0 560 210" preserveAspectRatio="none" className="chart-svg">
    {[0, 1, 2, 3, 4, 5].map((index) => <line key={`h${index}`} x1="36" x2="554" y1={14 + index * 36} y2={14 + index * 36} className="grid-line"/>)}
    {[0, 1, 2, 3, 4, 5].map((index) => <line key={`v${index}`} y1="12" y2="194" x1={36 + index * 103.6} x2={36 + index * 103.6} className="grid-line"/>)}
    {children}
  </svg><div className="x-axis">{xLabel}</div></div>;
}

function ConvergenceChart({ rounds }: { rounds: Round[] }) {
  if (!rounds.length) return <div className="card chart-card convergence"><div className="panel-title">Model Convergence</div><EmptyData text="No completed training rounds yet"/></div>;
  const train = rounds.map((round) => Math.max(0.001, round.mean_client_loss));
  const test = rounds.flatMap((round) => round.evaluation_loss === null ? [] : [Math.max(0.001, round.evaluation_loss)]);
  const accuracy = rounds.flatMap((round) => round.evaluation_accuracy === null ? [] : [Math.max(0, Math.min(1, round.evaluation_accuracy))]);
  const normalizeLog = (values: number[]) => values.map((value) => Math.log10(value + 0.01));
  return <div className="card chart-card convergence"><div className="panel-title">Model Convergence</div><div className="legend"><span className="blue">Train Loss</span><span className="orange">Evaluation Loss</span><span className="green">Evaluation Accuracy</span></div><ChartGrid yLabels={["10¹", "10⁰", "10⁻¹", "10⁻²"]}>
    <path d={pathFor(normalizeLog(train), 560, 210, 36, -2, 1)} className="line blue-line"/>
    {test.length > 0 && <path d={pathFor(normalizeLog(test), 560, 210, 36, -2, 1)} className="line orange-line"/>}
    {accuracy.length > 0 && <path d={pathFor(accuracy, 560, 210, 36, 0, 1)} className="line green-line"/>}
  </ChartGrid></div>;
}

function AggregationChart({ rounds }: { rounds: Round[] }) {
  if (!rounds.length) return <div className="card chart-card"><div className="panel-title">Aggregation Metrics</div><EmptyData text="No aggregation results yet"/></div>;
  const source = rounds.slice(-12);
  const counts = source.map((round) => Math.max(round.completed_clients?.length ?? 0, round.malicious_results));
  const scale = 160 / Math.max(1, ...counts);
  return <div className="card chart-card"><div className="panel-title">Aggregation Metrics</div><div className="legend"><span className="green-box">Benign Results</span><span className="red-box">Malicious Results</span></div><ChartGrid>
    {source.map((round, index) => {
      const completed = round.completed_clients?.length ?? 0;
      const malicious = Math.min(completed, round.malicious_results);
      const benign = Math.max(0, completed - malicious);
      const x = 52 + index * 40;
      return <g key={round.round_id}><rect x={x} y={194 - benign * scale} width="12" height={benign * scale} rx="1" className="bar-green"/><rect x={x} y={194 - (benign + malicious) * scale} width="12" height={malicious * scale} rx="1" className="bar-red"/></g>;
    })}
  </ChartGrid></div>;
}

function ResourceChart({ samples }: { samples: SystemSample[] }) {
  if (!samples.length) return <div className="card chart-card resource-card" id="system"><div className="panel-title">Resource Usage</div><EmptyData text="No live system samples yet"/></div>;
  const recent = samples.slice(-60);
  const cpu = recent.map((sample) => sample.cpuPercent);
  const memory = recent.map((sample) => sample.memoryPercent);
  const gpu = recent.flatMap((sample) => sample.gpuMemoryPercent === null ? [] : [sample.gpuMemoryPercent]);
  return <div className="card chart-card resource-card" id="system"><div className="panel-heading"><div className="panel-title">Resource Usage</div><div className="legend"><span className="blue">CPU</span><span className="green">Memory</span>{gpu.length > 0 && <span style={{ color: "#8268ff" }}>GPU Memory</span>}</div></div><ChartGrid xLabel="Live sample">
    <path d={pathFor(cpu, 560, 210, 36, 0, 100)} className="line blue-line"/>
    <path d={pathFor(memory, 560, 210, 36, 0, 100)} className="line green-line"/>
    {gpu.length > 0 && <path d={pathFor(gpu, 560, 210, 36, 0, 100)} className="line purple-line"/>}
  </ChartGrid></div>;
}

function Topology({ workers }: { workers: Worker[] }) {
  const list = workers.slice(0, 4);
  return <div className="card topology-card"><div className="panel-title">Network Topology</div>{list.length === 0 ? <EmptyData text="No worker processes reported yet"/> : <div className="topology-stage"><svg className="topology-lines" viewBox="0 0 600 210" preserveAspectRatio="none"><line x1="300" y1="105" x2="90" y2="42"/><line x1="300" y1="105" x2="90" y2="168"/><line x1="300" y1="105" x2="510" y2="42"/><line x1="300" y1="105" x2="510" y2="168"/></svg>
    <div className="coordinator-node"><div className="hex"><Icon name="cpu" size={24}/></div><span>Coordinator</span></div>
    {list.map((worker, index) => { const position = ["tl", "bl", "tr", "br"][index]; return <div className={`worker-node ${position}`} key={worker.id}><div className={`node-dot ${worker.role === "Malicious" ? "bad" : "good"}`}></div><span>{worker.id}</span><small className={worker.role === "Malicious" ? "bad-text" : "good-text"}>({worker.role})</small></div>; })}
    <div className="topology-legend"><span><i className="legend-dot coord"></i>Coordinator</span><span><i className="legend-dot good"></i>Benign Worker</span><span><i className="legend-dot bad"></i>Malicious Worker</span></div>
  </div>}</div>;
}

function WorkerTable({ workers }: { workers: Worker[] }) {
  const columns = { gridTemplateColumns: "1.25fr 1fr 1fr 1.2fr 1fr .85fr .85fr" };
  return <div className="card workers-card" id="workers"><div className="panel-title">Worker Status</div>{workers.length === 0 ? <EmptyData text="No worker process data available yet"/> : <div className="worker-table"><div className="worker-row worker-head" style={columns}><span>ID</span><span>Role</span><span>Status</span><span>Last Update</span><span>Sim. Latency</span><span>Samples</span><span>Loss</span></div>{workers.map((worker) => <div className="worker-row" style={columns} key={worker.id}><span className="worker-id"><i className={`status-dot ${worker.status === "Online" ? "green" : "red"}`}></i>{worker.id}</span><span><b className={`pill ${worker.role === "Malicious" ? "danger" : "benign"}`}>{worker.role}</b></span><span><b className={`pill ${worker.status === "Online" ? "online" : "danger"}`}><i></i>{worker.status}</b></span><span>{formatAge(worker.lastUpdateAt)}</span><span>{worker.latencyMs === null ? "—" : `${worker.latencyMs} ms`}</span><span>{worker.dataSize.toLocaleString("en-US")}</span><span>{worker.loss === null ? "—" : worker.loss.toFixed(4)}</span></div>)}</div>}</div>;
}

function Logs({ logs }: { logs: string[] }) {
  return <div className="card logs-card" id="logs"><div className="panel-heading"><div className="panel-title">Live Logs</div></div>{logs.length === 0 ? <EmptyData text="No runtime log lines received yet"/> : <pre className="log-window">{logs.slice(-12).map((line, index) => <span key={`${index}-${line}`} className={line.includes("MALICIOUS") || line.includes("ATTACK") ? "log-red" : line.includes("SECURITY") ? "log-yellow" : line.includes("WORKER") ? "log-green" : line.includes("CPP") ? "log-magenta" : "log-blue"}>{line}{"\n"}</span>)}</pre>}</div>;
}

function LiveConfiguration({ data }: { data: DashboardPayload }) {
  const unavailable = "—";
  return <div className="card controls-card" id="settings"><div className="control-title">Live Configuration</div><div className="control-grid three"><label>Attack<input value={data.available ? (data.attack ?? unavailable) : unavailable} readOnly/></label><label>Aggregator<input value={data.available ? (data.aggregator ?? unavailable) : unavailable} readOnly/></label><label>Device<input value={data.available ? (data.device ?? unavailable) : unavailable} readOnly/></label></div><div className="control-title training-title">Training State</div><div className="control-grid three"><label>Total Rounds<input value={data.available ? (data.totalRounds ?? unavailable) : unavailable} readOnly/></label><label>Benign Workers<input value={data.available ? data.benignWorkers : unavailable} readOnly/></label><label>Malicious Workers<input value={data.available ? data.maliciousWorkers : unavailable} readOnly/></label></div></div>;
}

export default function Dashboard() {
  const [data, setData] = useState<DashboardPayload>(EMPTY);
  const [activeNav, setActiveNav] = useState("overview");
  const [elapsed, setElapsed] = useState(0);
  const [stopping, setStopping] = useState(false);
  const [stopNotice, setStopNotice] = useState("");

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const response = await fetch("/api/dashboard", { cache: "no-store" });
        if (response.ok) {
          const next = await response.json() as DashboardPayload;
          if (mounted) setData(next);
        }
      } catch {
        if (mounted) setData(EMPTY);
      }
    };
    load();
    const id = setInterval(load, 1000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  useEffect(() => {
    setElapsed(data.elapsedSeconds);
    const id = setInterval(() => setElapsed((value) => data.active ? value + 1 : value), 1000);
    return () => clearInterval(id);
  }, [data.active, data.elapsedSeconds]);

  const rounds = data.rounds;
  const last = rounds.at(-1);
  const previous = rounds.at(-2);
  const accuracy = last?.evaluation_accuracy === null || last?.evaluation_accuracy === undefined ? null : last.evaluation_accuracy * 100;
  const loss = last?.evaluation_loss ?? null;
  const accuracyDelta = accuracy !== null && previous?.evaluation_accuracy !== null && previous?.evaluation_accuracy !== undefined ? accuracy - previous.evaluation_accuracy * 100 : null;
  const lossDelta = loss !== null && previous?.evaluation_loss !== null && previous?.evaluation_loss !== undefined ? loss - previous.evaluation_loss : null;
  const mitigation = useMemo(() => {
    const attacked = rounds.filter((round) => round.attack_mitigated !== null);
    return attacked.length ? attacked.filter((round) => round.attack_mitigated).length / attacked.length : null;
  }, [rounds]);
  const avgRound = rounds.length ? rounds.reduce((sum, round) => sum + round.round_duration_ms, 0) / rounds.length / 1000 : null;
  const configuredWorkers = data.benignWorkers + data.maliciousWorkers;
  const onlineWorkers = data.workers.filter((worker) => worker.status === "Online").length;
  const sparkAccuracy = rounds.flatMap((round) => round.evaluation_accuracy === null ? [] : [round.evaluation_accuracy * 100]);
  const sparkLoss = rounds.flatMap((round) => round.evaluation_loss === null ? [] : [round.evaluation_loss]);
  const sparkTime = rounds.map((round) => round.round_duration_ms / 1000);
  const mitigationPoints = rounds.flatMap((round) => round.mitigation_score === null ? [] : [round.mitigation_score * 100]);

  const stop = async () => {
    setStopping(true);
    setStopNotice("");
    try {
      const response = await fetch("/api/dashboard", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command: "stop" }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({})) as { error?: string };
        setStopNotice(body.error ?? "Stop request was rejected");
      }
    } catch {
      setStopNotice("Stop request could not reach the dashboard API");
    } finally {
      setStopping(false);
    }
  };

  return <div className="dashboard-shell">
    <header className="topbar"><div className="brand"><ShieldLogo/><div><h1>ZeroTrust-FL-Sim</h1><p>Secure <i/> Private <i/> Resilient <i/> Scalable</p></div></div><div className="top-actions"><div className="status-chip"><span className={`pulse ${data.active ? "on" : ""}`}></span>{!data.available ? "Live data unavailable" : data.active ? "Training Active" : "Training Idle"}</div><div className="header-chip">Round {data.currentRound ?? "—"} / {data.totalRounds ?? "—"}</div><div className="header-chip"><Icon name="clock" size={18}/>{data.available ? fmtDuration(elapsed) : "—"}</div><button className="stop-button" onClick={stop} disabled={stopping || !data.active}><Icon name="stop" size={17}/>{stopping ? "Stopping…" : "Stop Training"}</button></div></header>
    <aside className="sidebar"><nav>{NAV.map(([id, label, icon]) => <button key={id} className={activeNav === id ? "active" : ""} onClick={() => setActiveNav(id)}><Icon name={icon} size={21}/><span>{label}</span></button>)}</nav><div className="sidebar-footer"><strong>ZeroTrust-FL-Sim</strong><p>Live federated learning telemetry</p><div className="operational">{data.available && <i/>}{data.available ? `State updated ${formatAge(data.updatedAt)}` : "Waiting for runtime state"}</div></div></aside>
    <main className="content">
      {!data.available && <div className="card live-data-banner" style={{ padding: "12px 16px", marginBottom: 12 }}>No simulator state is available. Start the training stack to populate this dashboard. No preview or synthetic values are displayed.</div>}
      {stopNotice && <div className="toast">{stopNotice}</div>}
      <section className="kpi-grid">
        <Kpi icon="target" title="Global Accuracy" value={accuracy === null ? "—" : `${accuracy.toFixed(2)}%`} trend={accuracyDelta === null ? undefined : `${accuracyDelta >= 0 ? "↑" : "↓"} ${accuracyDelta >= 0 ? "+" : ""}${accuracyDelta.toFixed(2)}%`} points={sparkAccuracy}/>
        <Kpi icon="loss" title="Global Loss" value={loss === null ? "—" : loss.toFixed(3)} trend={lossDelta === null ? undefined : `${lossDelta <= 0 ? "↓" : "↑"} ${lossDelta >= 0 ? "+" : ""}${lossDelta.toFixed(3)}`} tone="green" points={sparkLoss}/>
        <div className="card kpi-card active-workers"><div className="kpi-icon"><Icon name="workers" size={30}/></div><div className="kpi-copy"><div className="kpi-title">Active Workers</div><div className="kpi-value">{data.available ? `${onlineWorkers} / ${configuredWorkers}` : "—"}</div><div className="kpi-sub">{data.available ? `${data.benignWorkers} benign, ${data.maliciousWorkers} malicious` : "No runtime worker data"}</div></div><div className="worker-progress"><div style={{ width: `${data.available && configuredWorkers ? onlineWorkers / configuredWorkers * 100 : 0}%` }}></div></div></div>
        <Kpi icon="shield" title="Mitigation Rate" value={mitigation === null ? "—" : `${(mitigation * 100).toFixed(1)}%`} tone="green" points={mitigationPoints}/>
        <Kpi icon="clock" title="Avg. Round Time" value={avgRound === null ? "—" : `${avgRound.toFixed(1)}s`} points={sparkTime}/>
      </section>
      <section className="charts-grid" id="metrics"><ConvergenceChart rounds={rounds}/><AggregationChart rounds={rounds}/><ResourceChart samples={data.systemSamples}/></section>
      <section className="middle-grid"><WorkerTable workers={data.workers}/><Topology workers={data.workers}/></section>
      <section className="bottom-grid"><Logs logs={data.logs}/><LiveConfiguration data={data}/></section>
    </main>
  </div>;
}
