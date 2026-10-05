/**
 * TypeScript NativeClient — mirrors Python connector_sdk.native.
 * Defaults to http://127.0.0.1:9091. Refuses silent dev-token outside lab.
 */

export type RuntimeProfile = string;

export class NativeClientError extends Error {
  status?: number;
  body?: unknown;
  constructor(message: string, opts?: { status?: number; body?: unknown }) {
    super(message);
    this.name = "NativeClientError";
    this.status = opts?.status;
    this.body = opts?.body;
  }
}

export type PackagePin = {
  schema?: string;
  package_id: string;
  package_digest: string;
  kind?: string;
  ir_digest?: string;
  signature_present?: boolean;
};

function runtimeProfile(): string {
  return (process.env.CONNECTOR_RUNTIME_PROFILE || "development").trim().toLowerCase();
}

function isLabProfile(profile?: string): boolean {
  const p = (profile || runtimeProfile()).toLowerCase();
  return ["lab", "dev", "development", "test"].includes(p);
}

export function admitPackageForEffect(
  packagePin: PackagePin | null | undefined,
  opts: { mutates: boolean; profile?: string }
): void {
  if (!opts.mutates) return;
  const prof = (opts.profile || runtimeProfile()).toLowerCase();
  if (isLabProfile(prof) && !packagePin) return;
  if (!packagePin) {
    throw new NativeClientError(
      "package_required: mutating native invoke needs signed AppPackageV2 pin outside lab"
    );
  }
  const digest = String(packagePin.package_digest || "").trim();
  const pkgId = String(packagePin.package_id || "").trim();
  if (!pkgId || digest.length < 16) {
    throw new NativeClientError("package_invalid_pin: package_id and package_digest required");
  }
  if (
    ["production", "hardened", "defense", "defense-strict", "defense_strict"].includes(prof)
  ) {
    if (packagePin.signature_present !== true) {
      throw new NativeClientError(
        "package_unsigned: signature_present required under production profile"
      );
    }
  }
}

export type NativeClientOptions = {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
  runtimeProfile?: string;
  enforcePackageGate?: boolean;
};

export class NativeClient {
  readonly baseUrl: string;
  readonly runtimeProfile: string;
  readonly enforcePackageGate: boolean;
  private token: string;
  private timeoutMs: number;

  constructor(opts: NativeClientOptions = {}) {
    const envUrl = process.env.CONNECTOR_BASE_URL || process.env.CONNECTOR_NATIVE_URL;
    this.baseUrl = (opts.baseUrl || envUrl || "http://127.0.0.1:9091").replace(/\/$/, "");
    this.runtimeProfile = (opts.runtimeProfile || runtimeProfile()).toLowerCase();
    this.enforcePackageGate = opts.enforcePackageGate !== false;
    this.timeoutMs = opts.timeoutMs ?? 30_000;

    let token = opts.token ?? process.env.CONNECTOR_TOKEN ?? process.env.CONNECTOR_API_TOKEN;
    if (!token) {
      if (isLabProfile(this.runtimeProfile)) {
        token = process.env.CONNECTOR_LAB_TOKEN || "";
      } else {
        throw new NativeClientError(
          "token_required: set CONNECTOR_TOKEN or pass token= (no silent dev-token outside lab)"
        );
      }
    }
    if (token === "dev-token" && !isLabProfile(this.runtimeProfile)) {
      throw new NativeClientError(
        "token_refused: silent/default dev-token is not allowed outside lab profile"
      );
    }
    this.token = token;
  }

  private url(path: string): string {
    return `${this.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
  }

  private async request(method: string, path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      "Content-Type": "application/json",
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    try {
      const res = await fetch(this.url(path), {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: ctrl.signal,
      });
      let data: unknown = null;
      try {
        data = await res.json();
      } catch {
        data = { raw: await res.text().catch(() => "") };
      }
      if (!res.ok) {
        const err =
          data && typeof data === "object"
            ? (data as Record<string, unknown>).error ||
              (data as Record<string, unknown>).message ||
              (data as Record<string, unknown>).honesty
            : undefined;
        throw new NativeClientError(String(err || `http_${res.status}`), {
          status: res.status,
          body: data,
        });
      }
      if (data && typeof data === "object" && (data as Record<string, unknown>).ok === false) {
        throw new NativeClientError(
          String(
            (data as Record<string, unknown>).error ||
              (data as Record<string, unknown>).honesty ||
              "request_denied"
          ),
          { status: res.status, body: data }
        );
      }
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  listSurfaces(): Promise<unknown> {
    return this.request("GET", "/api/v1/native/surfaces");
  }

  listChannels(): Promise<unknown> {
    return this.request("GET", "/api/v1/native/channels");
  }

  getReceipt(operationId: string): Promise<unknown> {
    return this.request("GET", `/api/v1/native/receipts/${operationId}`);
  }

  evidenceGraph(opts?: { limit?: number; intelligence?: string }): Promise<unknown> {
    const limit = opts?.limit ?? 64;
    let q = `/api/v1/native/evidence/graph?limit=${limit}`;
    if (opts?.intelligence) q += `&intelligence=${encodeURIComponent(opts.intelligence)}`;
    return this.request("GET", q);
  }

  invoke(body: Record<string, unknown>, packagePin?: PackagePin): Promise<unknown> {
    const effect = (body.effect || {}) as { mutates?: boolean };
    const mutates = Boolean(effect.mutates);
    if (this.enforcePackageGate) {
      admitPackageForEffect(packagePin, {
        mutates,
        profile: this.runtimeProfile,
      });
    }
    const payload = { ...body };
    if (packagePin) payload.package = packagePin;
    return this.request("POST", "/api/v1/native/invocations", payload);
  }
}
