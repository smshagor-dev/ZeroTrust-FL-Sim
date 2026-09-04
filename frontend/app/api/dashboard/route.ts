import { promises as fs } from "node:fs";
import path from "node:path";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ROOT = path.resolve(process.cwd(), "..");
const RUNTIME = path.join(ROOT, "tmp", "orchestrator");
const STATE = path.join(RUNTIME, "dashboard-state.json");
const COMMAND = path.join(RUNTIME, "dashboard-command.json");
const LOG = path.join(RUNTIME, "dashboard.log");
const HEALTH = path.join(RUNTIME, "health");

const previewRounds = Array.from({ length: 12 }, (_, i) => ({
  round_id: i + 1,
  mean_client_loss: 1.7 * Math.exp(-i / 3.8) + 0.18,
  evaluation_loss: 1.35 * Math.exp(-i / 3.2) + 0.17,
  evaluation_accuracy: 0.18 + 0.74 * (1 - Math.exp(-i / 4.8)),
  malicious_results: 1,
  mitigation_score: 0.86 + i * 0.01,
  attack_mitigated: true,
  round_duration_ms: 12000 + ((i % 4) - 1) * 700,
}));

async function exists(file: string) {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as T;
  } catch {
    return null;
  }
}

async function readLogs() {
  try {
    const text = await fs.readFile(LOG, "utf8");
    return text.split(/\r?\n/).filter(Boolean).slice(-16);
  } catch {
    return [] as string[];
  }
}

async function workerStatus(benign: number, malicious: number) {
  const defs = [
    ...Array.from({ length: benign }, (_, i) => ({ id: `benign-worker-${i + 1}`, role: "Benign" as const })),
    ...Array.from({ length: malicious }, (_, i) => ({ id: `malicious-worker-${i + 1}`, role: "Malicious" as const })),
  ];
  return Promise.all(defs.map(async (worker, index) => {
    const file = path.join(HEALTH, `${worker.id}.ready`);
    const online = await exists(file);
    let lastUpdate = online ? "just now" : "—";
    if (online) {
      try {
        const stat = await fs.stat(file);
        const age = Math.max(0, Math.round((Date.now() - stat.mtimeMs) / 1000));
        lastUpdate = age < 2 ? "1s ago" : `${age}s ago`;
      } catch {}
    }
    return {
      id: `worker-${index + 1}`,
      role: worker.role,
      status: online ? "Online" as const : "Offline" as const,
      lastUpdate,
      latencyMs: [12, 15, 11, 14, 13, 16][index % 6],
      dataSize: 1024,
    };
  }));
}

type StateFile = {
  active?: boolean;
  started_at?: number;
  updated_at?: number;
  current_round?: number;
  total_rounds?: number;
  attack?: string;
  aggregator?: string;
  device?: string;
  benign_workers?: number;
  malicious_workers?: number;
  rounds?: unknown[];
  logs?: string[];
};

export async function GET() {
  const state = await readJson<StateFile>(STATE);
  const live = Boolean(state);
  const benign = state?.benign_workers ?? 3;
  const malicious = state?.malicious_workers ?? 1;
  const rounds = Array.isArray(state?.rounds) && state.rounds.length ? state.rounds : previewRounds;
  const startedAt = state?.started_at ?? Date.now() / 1000 - 1104;
  const active = state?.active ?? true;
  const runtimeLogs = await readLogs();
  const logs = Array.isArray(state?.logs) && state.logs.length ? state.logs : runtimeLogs;

  return NextResponse.json({
    mode: live ? "live" : "preview",
    active,
    startedAt,
    elapsedSeconds: Math.max(0, Math.floor(Date.now() / 1000 - startedAt)),
    currentRound: state?.current_round ?? (live ? rounds.length : 12),
    totalRounds: state?.total_rounds ?? (live ? Math.max(rounds.length, 5) : 50),
    attack: state?.attack ?? "gaussian",
    aggregator: state?.aggregator ?? "median",
    device: state?.device ?? "cpu",
    benignWorkers: benign,
    maliciousWorkers: malicious,
    rounds,
    workers: live ? await workerStatus(benign, malicious) : [
      { id: "worker-1", role: "Benign", status: "Online", lastUpdate: "2s ago", latencyMs: 12, dataSize: 1024 },
      { id: "worker-2", role: "Benign", status: "Online", lastUpdate: "1s ago", latencyMs: 15, dataSize: 1024 },
      { id: "worker-3", role: "Benign", status: "Online", lastUpdate: "3s ago", latencyMs: 11, dataSize: 1024 },
      { id: "worker-4", role: "Malicious", status: "Online", lastUpdate: "2s ago", latencyMs: 14, dataSize: 1024 },
    ],
    logs,
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: Request) {
  const body = await request.json().catch(() => ({})) as { command?: string };
  if (body.command !== "stop") {
    return NextResponse.json({ ok: false, error: "unsupported command" }, { status: 400 });
  }
  await fs.mkdir(RUNTIME, { recursive: true });
  const tmp = `${COMMAND}.tmp`;
  await fs.writeFile(tmp, JSON.stringify({ command: "stop", created_at: Date.now() / 1000 }, null, 2), "utf8");
  await fs.rename(tmp, COMMAND);
  return NextResponse.json({ ok: true });
}
