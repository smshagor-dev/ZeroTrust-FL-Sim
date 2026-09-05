import { timingSafeEqual } from "node:crypto";
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

type WorkerState = {
  id?: string;
  role?: "Benign" | "Malicious";
  status?: "Online" | "Offline";
  last_update_at?: number | null;
  latency_ms?: number | null;
  data_size?: number | null;
  training_duration_ms?: number | null;
  loss?: number | null;
  last_round?: number | null;
};

type SystemSampleState = {
  timestamp?: number;
  cpu_percent?: number;
  memory_percent?: number;
  gpu_memory_percent?: number | null;
};

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
  workers?: WorkerState[];
  system_samples?: SystemSampleState[];
  logs?: string[];
};

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
    return text.split(/\r?\n/).filter(Boolean).slice(-48);
  } catch {
    return [] as string[];
  }
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function nonNegativeNumber(value: unknown): number | null {
  const number = finiteNumber(value);
  return number !== null && number >= 0 ? number : null;
}

function normalizeWorker(worker: WorkerState) {
  const dataSize = nonNegativeNumber(worker.data_size);
  if (
    !worker.id ||
    (worker.role !== "Benign" && worker.role !== "Malicious") ||
    dataSize === null
  ) {
    return null;
  }
  return {
    id: worker.id,
    role: worker.role,
    status: worker.status === "Online" ? "Online" : "Offline",
    lastUpdateAt: nonNegativeNumber(worker.last_update_at),
    latencyMs: nonNegativeNumber(worker.latency_ms),
    dataSize,
    trainingDurationMs: nonNegativeNumber(worker.training_duration_ms),
    loss: nonNegativeNumber(worker.loss),
    lastRound: nonNegativeNumber(worker.last_round),
  };
}

function normalizeSystemSample(sample: SystemSampleState) {
  const timestamp = nonNegativeNumber(sample.timestamp);
  const cpuPercent = nonNegativeNumber(sample.cpu_percent);
  const memoryPercent = nonNegativeNumber(sample.memory_percent);
  if (timestamp === null || cpuPercent === null || memoryPercent === null) {
    return null;
  }
  return {
    timestamp,
    cpuPercent,
    memoryPercent,
    gpuMemoryPercent: nonNegativeNumber(sample.gpu_memory_percent),
  };
}

function authorizedControlRequest(request: Request): boolean {
  const configured = process.env.ZTFL_DASHBOARD_CONTROL_TOKEN?.trim();
  if (!configured) {
    return false;
  }
  const authorization = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!authorization.startsWith(prefix)) {
    return false;
  }
  const provided = authorization.slice(prefix.length).trim();
  const expectedBytes = Buffer.from(configured, "utf8");
  const providedBytes = Buffer.from(provided, "utf8");
  return (
    expectedBytes.length === providedBytes.length &&
    timingSafeEqual(expectedBytes, providedBytes)
  );
}

export async function GET() {
  const state = await readJson<StateFile>(STATE);
  if (!state) {
    return NextResponse.json(
      {
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
      },
      { headers: { "Cache-Control": "no-store, max-age=0" } },
    );
  }

  const startedAt = nonNegativeNumber(state.started_at);
  const workers = Array.isArray(state.workers)
    ? state.workers.map(normalizeWorker).filter((worker) => worker !== null)
    : [];
  const systemSamples = Array.isArray(state.system_samples)
    ? state.system_samples
        .map(normalizeSystemSample)
        .filter((sample) => sample !== null)
        .slice(-120)
    : [];
  const runtimeLogs = await readLogs();
  const stateLogs = Array.isArray(state.logs)
    ? state.logs.filter((line): line is string => typeof line === "string")
    : [];
  const logs = Array.from(new Set([...runtimeLogs, ...stateLogs])).slice(-48);

  const derivedBenign = workers.filter((worker) => worker.role === "Benign").length;
  const derivedMalicious = workers.filter(
    (worker) => worker.role === "Malicious",
  ).length;

  return NextResponse.json(
    {
      available: true,
      active: Boolean(state.active),
      startedAt,
      updatedAt: nonNegativeNumber(state.updated_at),
      elapsedSeconds:
        startedAt === null
          ? 0
          : Math.max(0, Math.floor(Date.now() / 1000 - startedAt)),
      currentRound: nonNegativeNumber(state.current_round),
      totalRounds: nonNegativeNumber(state.total_rounds),
      attack: typeof state.attack === "string" ? state.attack : null,
      aggregator:
        typeof state.aggregator === "string" ? state.aggregator : null,
      device: typeof state.device === "string" ? state.device : null,
      benignWorkers:
        nonNegativeNumber(state.benign_workers) ?? derivedBenign,
      maliciousWorkers:
        nonNegativeNumber(state.malicious_workers) ?? derivedMalicious,
      rounds: Array.isArray(state.rounds) ? state.rounds : [],
      workers,
      systemSamples,
      logs,
    },
    { headers: { "Cache-Control": "no-store, max-age=0" } },
  );
}

export async function POST(request: Request) {
  if (!authorizedControlRequest(request)) {
    return NextResponse.json(
      {
        ok: false,
        error: process.env.ZTFL_DASHBOARD_CONTROL_TOKEN
          ? "unauthorized"
          : "dashboard control is disabled",
      },
      { status: process.env.ZTFL_DASHBOARD_CONTROL_TOKEN ? 401 : 503 },
    );
  }

  const body = (await request.json().catch(() => ({}))) as {
    command?: string;
  };
  if (body.command !== "stop") {
    return NextResponse.json(
      { ok: false, error: "unsupported command" },
      { status: 400 },
    );
  }

  await fs.mkdir(RUNTIME, { recursive: true });
  const tmp = `${COMMAND}.tmp`;
  await fs.writeFile(
    tmp,
    JSON.stringify(
      { command: "stop", created_at: Date.now() / 1000 },
      null,
      2,
    ),
    { encoding: "utf8", mode: 0o600 },
  );
  await fs.rename(tmp, COMMAND);
  return NextResponse.json({ ok: true });
}
