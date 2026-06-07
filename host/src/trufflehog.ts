import fs from "fs";
import os from "os";
import path from "path";
import { randomUUID } from "crypto";

import { extractTarGz } from "./alpine/tar.ts";

const TRUFFLEHOG_REGISTRY_SCHEMA = 1 as const;
const DEFAULT_TRUFFLEHOG_REF = "trufflehog:3.95.3";
const DEFAULT_TRUFFLEHOG_REGISTRY_URL =
  "https://raw.githubusercontent.com/earendil-works/gondolin/main/builtin-trufflehog-registry.json";

type SupportedPlatform =
  | "darwin-arm64"
  | "darwin-x64"
  | "linux-arm64"
  | "linux-x64";

type TrufflehogRegistryBuild = {
  /** tool version */
  version: string;
  /** target platform */
  platform: SupportedPlatform;
  /** binary archive url */
  url: string;
  /** binary archive checksum */
  sha256?: string;
  /** source archive url */
  sourceUrl?: string;
  /** source archive checksum */
  sourceSha256?: string;
};

type BuiltinTrufflehogRegistry = {
  /** registry schema version */
  schema: typeof TRUFFLEHOG_REGISTRY_SCHEMA;
  /** named refs mapped by platform to build ids */
  refs: Record<string, Partial<Record<SupportedPlatform, string>>>;
  /** build-id keyed sources */
  builds: Record<string, TrufflehogRegistryBuild>;
};

type RegistryCache = {
  /** source registry url */
  url: string;
  /** http etag */
  etag?: string;
  /** cached registry */
  registry: BuiltinTrufflehogRegistry;
};

export interface EnsureTrufflehogOptions {
  /** explicit binary path override */
  binaryPath?: string;
  /** explicit cache/store directory */
  storeDir?: string;
  /** optional logger */
  log?: (msg: string) => void;
}

export interface TrufflehogStatus {
  /** helper ref */
  ref: string;
  /** helper version */
  version: string;
  /** resolved platform key */
  platform: SupportedPlatform;
  /** configured binary override path */
  configuredPath: string | null;
  /** configured directory override */
  configuredDir: string | null;
  /** managed install path */
  managedPath: string;
  /** whether a managed binary already exists */
  installed: boolean;
  /** download url for this platform */
  downloadUrl: string;
  /** build id */
  buildId: string;
}

function cacheBaseDir(): string {
  return process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
}

export function getTrufflehogStoreDirectory(): string {
  return (
    process.env.GONDOLIN_TRUFFLEHOG_STORE ??
    path.join(cacheBaseDir(), "gondolin", "tools", "trufflehog")
  );
}

function trufflehogRegistryUrl(value?: string): string {
  const envValue = process.env.GONDOLIN_TRUFFLEHOG_REGISTRY_URL?.trim();
  const explicit = value?.trim();
  if (explicit) return explicit;
  if (envValue) return envValue;
  return DEFAULT_TRUFFLEHOG_REGISTRY_URL;
}

function registryCachePath(storeDir: string): string {
  return path.join(storeDir, "builtin-trufflehog-registry-cache.json");
}

function objectDir(storeDir: string, buildId: string): string {
  return path.join(storeDir, "objects", buildId);
}

function installedBinaryPath(storeDir: string, buildId: string): string {
  return path.join(objectDir(storeDir, buildId), "bin", "trufflehog");
}

function installedSourcePath(storeDir: string, buildId: string): string {
  return path.join(objectDir(storeDir, buildId), "source");
}

function normalizeSupportedPlatform(value: string): SupportedPlatform | null {
  if (value === "darwin-arm64") return value;
  if (value === "darwin-x64") return value;
  if (value === "linux-arm64") return value;
  if (value === "linux-x64") return value;
  return null;
}

function resolveSupportedPlatform(
  platform: string = process.platform,
  arch: string = process.arch,
): SupportedPlatform {
  if (platform === "darwin" && arch === "arm64") return "darwin-arm64";
  if (platform === "darwin" && (arch === "x64" || arch === "amd64")) {
    return "darwin-x64";
  }
  if (platform === "linux" && arch === "arm64") return "linux-arm64";
  if (platform === "linux" && (arch === "x64" || arch === "amd64")) {
    return "linux-x64";
  }
  throw new Error(
    `trufflehog helper is not available for this platform: ${platform}/${arch}`,
  );
}

function resolveConfiguredBinaryPath(explicit?: string): string | null {
  const candidate =
    explicit?.trim() || process.env.GONDOLIN_TRUFFLEHOG_PATH?.trim();
  if (!candidate) return null;
  const resolved = path.resolve(candidate);
  if (!fs.existsSync(resolved)) {
    throw new Error(`configured trufflehog binary does not exist: ${candidate}`);
  }
  return resolved;
}

function resolveConfiguredDirectory(): string | null {
  const candidate = process.env.GONDOLIN_TRUFFLEHOG_DIR?.trim();
  if (!candidate) return null;
  const resolved = path.resolve(candidate);
  if (!fs.existsSync(path.join(resolved, "trufflehog"))) {
    throw new Error(
      `configured trufflehog directory does not contain a trufflehog binary: ${candidate}`,
    );
  }
  return resolved;
}

function parseRef(reference: string): string {
  const trimmed = reference.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*:[A-Za-z0-9][A-Za-z0-9._+-]*$/.test(trimmed)) {
    throw new Error(`invalid trufflehog ref: ${reference}`);
  }
  return trimmed;
}

function normalizeSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`invalid ${label}: expected sha256 hex string`);
  }
  return value.toLowerCase();
}

function parseRegistryBuild(
  raw: unknown,
  where: string,
  baseUrl: URL,
): TrufflehogRegistryBuild {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`invalid ${where}: expected object`);
  }
  const rec = raw as Record<string, unknown>;
  if (typeof rec.version !== "string" || !rec.version) {
    throw new Error(`invalid ${where}.version: expected string`);
  }
  if (typeof rec.platform !== "string") {
    throw new Error(`invalid ${where}.platform: expected string`);
  }
  const platform = normalizeSupportedPlatform(rec.platform);
  if (!platform) {
    throw new Error(`invalid ${where}.platform: ${String(rec.platform)}`);
  }
  if (typeof rec.url !== "string") {
    throw new Error(`invalid ${where}.url: expected string`);
  }

  let url: string;
  try {
    url = new URL(rec.url, baseUrl).toString();
  } catch {
    throw new Error(`invalid ${where}.url: ${rec.url}`);
  }

  const build: TrufflehogRegistryBuild = {
    version: rec.version,
    platform,
    url,
  };

  if (rec.sha256 !== undefined) {
    build.sha256 = normalizeSha256(rec.sha256, `${where}.sha256`);
  }
  if (rec.sourceUrl !== undefined) {
    if (typeof rec.sourceUrl !== "string") {
      throw new Error(`invalid ${where}.sourceUrl: expected string`);
    }
    try {
      build.sourceUrl = new URL(rec.sourceUrl, baseUrl).toString();
    } catch {
      throw new Error(`invalid ${where}.sourceUrl: ${rec.sourceUrl}`);
    }
  }
  if (rec.sourceSha256 !== undefined) {
    build.sourceSha256 = normalizeSha256(
      rec.sourceSha256,
      `${where}.sourceSha256`,
    );
  }

  return build;
}

function parseBuiltinTrufflehogRegistry(
  raw: unknown,
  sourceUrl: string,
): BuiltinTrufflehogRegistry {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("invalid builtin trufflehog registry: expected object");
  }
  const rec = raw as Record<string, unknown>;
  if (rec.schema !== TRUFFLEHOG_REGISTRY_SCHEMA) {
    throw new Error(
      `invalid builtin trufflehog registry schema: expected ${TRUFFLEHOG_REGISTRY_SCHEMA}`,
    );
  }
  const baseUrl = new URL(sourceUrl);

  if (!rec.builds || typeof rec.builds !== "object" || Array.isArray(rec.builds)) {
    throw new Error("invalid builtin trufflehog registry: builds must be an object");
  }
  const builds: Record<string, TrufflehogRegistryBuild> = {};
  for (const [buildId, value] of Object.entries(rec.builds as Record<string, unknown>)) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(buildId)) {
      throw new Error(`invalid builtin trufflehog build id: ${buildId}`);
    }
    builds[buildId] = parseRegistryBuild(value, `builds['${buildId}']`, baseUrl);
  }

  if (!rec.refs || typeof rec.refs !== "object" || Array.isArray(rec.refs)) {
    throw new Error("invalid builtin trufflehog registry: refs must be an object");
  }
  const refs: Record<string, Partial<Record<SupportedPlatform, string>>> = {};
  for (const [reference, value] of Object.entries(rec.refs as Record<string, unknown>)) {
    const canonical = parseRef(reference);
    if (canonical !== reference) {
      throw new Error(`invalid builtin trufflehog registry ref key: ${reference}`);
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`invalid registry ref '${reference}': expected object`);
    }
    const mapped: Partial<Record<SupportedPlatform, string>> = {};
    for (const [platformKey, buildIdValue] of Object.entries(value as Record<string, unknown>)) {
      const platform = normalizeSupportedPlatform(platformKey);
      if (!platform) {
        throw new Error(`invalid registry ref '${reference}' platform key: ${platformKey}`);
      }
      if (typeof buildIdValue !== "string") {
        throw new Error(
          `invalid refs['${reference}']['${platformKey}']: expected build id string`,
        );
      }
      const build = builds[buildIdValue];
      if (!build) {
        throw new Error(
          `invalid refs['${reference}']['${platformKey}']: unknown build id ${buildIdValue}`,
        );
      }
      if (build.platform !== platform) {
        throw new Error(
          `invalid refs['${reference}']['${platformKey}']: platform mismatch for build ${buildIdValue}`,
        );
      }
      mapped[platform] = buildIdValue;
    }
    refs[canonical] = mapped;
  }

  return { schema: TRUFFLEHOG_REGISTRY_SCHEMA, refs, builds };
}

function loadRegistryCache(url: string, storeDir: string): RegistryCache | null {
  const cachePath = registryCachePath(storeDir);
  if (!fs.existsSync(cachePath)) return null;

  try {
    const parsed = JSON.parse(fs.readFileSync(cachePath, "utf8")) as RegistryCache;
    if (!parsed || typeof parsed !== "object") return null;
    if (parsed.url !== url) return null;
    return {
      url,
      etag: typeof parsed.etag === "string" ? parsed.etag : undefined,
      registry: parseBuiltinTrufflehogRegistry(parsed.registry as unknown, url),
    };
  } catch {
    return null;
  }
}

function saveRegistryCache(cache: RegistryCache, storeDir: string): void {
  fs.mkdirSync(storeDir, { recursive: true });
  const cachePath = registryCachePath(storeDir);
  const tmpPath = `${cachePath}.tmp-${randomUUID().slice(0, 8)}`;
  fs.writeFileSync(tmpPath, JSON.stringify(cache, null, 2));
  fs.renameSync(tmpPath, cachePath);
}

async function fetchBuiltinTrufflehogRegistry(options: {
  registryUrl?: string;
  storeDir?: string;
}): Promise<BuiltinTrufflehogRegistry> {
  const storeDir = options.storeDir ?? getTrufflehogStoreDirectory();
  const url = trufflehogRegistryUrl(options.registryUrl);
  const cached = loadRegistryCache(url, storeDir);

  const headers: Record<string, string> = {
    "User-Agent": "gondolin-trufflehog-registry",
  };
  if (cached?.etag) {
    headers["If-None-Match"] = cached.etag;
  }

  let response: Response;
  try {
    response = await fetch(url, { headers });
  } catch (error) {
    if (cached) return cached.registry;
    throw new Error(
      `failed to fetch builtin trufflehog registry from ${url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (response.status === 304 && cached) {
    return cached.registry;
  }
  if (!response.ok) {
    if (cached) return cached.registry;
    throw new Error(
      `failed to fetch builtin trufflehog registry: ${response.status} ${response.statusText} (${url})`,
    );
  }

  const text = await response.text();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `failed to parse builtin trufflehog registry json from ${url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const registry = parseBuiltinTrufflehogRegistry(raw, url);
  saveRegistryCache(
    {
      url,
      etag: response.headers.get("etag") ?? undefined,
      registry,
    },
    storeDir,
  );
  return registry;
}

async function resolveManagedBuild(
  storeDir: string,
  platform: SupportedPlatform,
): Promise<{ ref: string; buildId: string; build: TrufflehogRegistryBuild }> {
  const registry = await fetchBuiltinTrufflehogRegistry({ storeDir });
  const ref = parseRef(DEFAULT_TRUFFLEHOG_REF);
  const entries = registry.refs[ref];
  if (!entries) {
    throw new Error(`trufflehog ref not found in builtin registry: ${ref}`);
  }
  const buildId = entries[platform];
  if (!buildId) {
    throw new Error(
      `trufflehog ref '${ref}' has no registry source for ${platform}`,
    );
  }
  const build = registry.builds[buildId];
  if (!build) {
    throw new Error(
      `trufflehog ref '${ref}' points to unknown registry build id: ${buildId}`,
    );
  }
  return { ref, buildId, build };
}

async function downloadToBuffer(
  url: string,
  expectedSha256: string | undefined,
  userAgent: string,
): Promise<Buffer> {
  const response = await fetch(url, {
    headers: { "User-Agent": userAgent },
  });
  if (!response.ok) {
    throw new Error(
      `failed to download ${url}: ${response.status} ${response.statusText}`,
    );
  }
  const data = Buffer.from(await response.arrayBuffer());
  if (expectedSha256) {
    const hash = (await import("crypto")).createHash("sha256").update(data).digest("hex");
    if (hash !== expectedSha256) {
      throw new Error(
        `downloaded checksum mismatch for ${url}\n  expected: ${expectedSha256}\n  got:      ${hash}`,
      );
    }
  }
  return data;
}

function findBinary(rootDir: string): string | null {
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name === "trufflehog") {
        return fullPath;
      }
    }
  }
  return null;
}

async function installManagedBinary(
  storeDir: string,
  buildId: string,
  build: TrufflehogRegistryBuild,
  log?: (msg: string) => void,
): Promise<string> {
  const targetPath = installedBinaryPath(storeDir, buildId);
  if (fs.existsSync(targetPath)) return targetPath;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-trufflehog-"));
  const archivePath = path.join(tmpRoot, "trufflehog.tar.gz");
  const extractDir = path.join(tmpRoot, "extract");
  const installDir = path.dirname(targetPath);

  try {
    log?.(`Downloading trufflehog ${build.version} for ${build.platform}`);
    fs.writeFileSync(
      archivePath,
      await downloadToBuffer(build.url, build.sha256, "gondolin-trufflehog-fetch"),
    );
    fs.mkdirSync(extractDir, { recursive: true });
    await extractTarGz(archivePath, extractDir);

    const binary = findBinary(extractDir);
    if (!binary) {
      throw new Error("downloaded trufflehog archive did not contain a trufflehog binary");
    }

    fs.mkdirSync(path.dirname(installDir), { recursive: true });
    if (!fs.existsSync(targetPath)) {
      const tmpInstallDir = `${installDir}.tmp-${randomUUID().slice(0, 8)}`;
      try {
        fs.mkdirSync(tmpInstallDir, { recursive: true });
        fs.copyFileSync(binary, path.join(tmpInstallDir, "trufflehog"));
        fs.chmodSync(path.join(tmpInstallDir, "trufflehog"), 0o755);
        fs.renameSync(tmpInstallDir, installDir);
      } catch (error) {
        fs.rmSync(tmpInstallDir, { recursive: true, force: true });
        if (!fs.existsSync(targetPath)) throw error;
      }
    }

    fs.chmodSync(targetPath, 0o755);
    return targetPath;
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

export async function ensureTrufflehogSourceDir(
  options: Omit<EnsureTrufflehogOptions, "binaryPath"> = {},
): Promise<string> {
  const storeDir = options.storeDir ?? getTrufflehogStoreDirectory();
  const platform = resolveSupportedPlatform();
  const { buildId, build } = await resolveManagedBuild(storeDir, platform);
  const targetDir = installedSourcePath(storeDir, buildId);
  if (fs.existsSync(path.join(targetDir, "pkg", "detectors"))) {
    return targetDir;
  }
  if (!build.sourceUrl) {
    throw new Error(`trufflehog build ${buildId} does not provide sourceUrl`);
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-trufflehog-src-"));
  const archivePath = path.join(tmpRoot, "trufflehog-source.tar.gz");
  const extractDir = path.join(tmpRoot, "extract");

  try {
    options.log?.(`Downloading trufflehog source ${build.version}`);
    fs.writeFileSync(
      archivePath,
      await downloadToBuffer(
        build.sourceUrl,
        build.sourceSha256,
        "gondolin-trufflehog-source-fetch",
      ),
    );
    fs.mkdirSync(extractDir, { recursive: true });
    await extractTarGz(archivePath, extractDir);

    const extractedRoot = fs
      .readdirSync(extractDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(extractDir, entry.name))
      .find((dir) => fs.existsSync(path.join(dir, "pkg", "detectors")));
    if (!extractedRoot) {
      throw new Error(
        "downloaded trufflehog source archive did not contain pkg/detectors",
      );
    }

    fs.mkdirSync(path.dirname(targetDir), { recursive: true });
    if (!fs.existsSync(targetDir)) {
      const tmpInstallDir = `${targetDir}.tmp-${randomUUID().slice(0, 8)}`;
      try {
        fs.cpSync(extractedRoot, tmpInstallDir, { recursive: true });
        fs.renameSync(tmpInstallDir, targetDir);
      } catch (error) {
        fs.rmSync(tmpInstallDir, { recursive: true, force: true });
        if (!fs.existsSync(targetDir)) throw error;
      }
    }

    return targetDir;
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

export async function ensureTrufflehogBinary(
  options: EnsureTrufflehogOptions = {},
): Promise<string> {
  const configuredPath = resolveConfiguredBinaryPath(options.binaryPath);
  if (configuredPath) return configuredPath;

  const configuredDir = resolveConfiguredDirectory();
  if (configuredDir) return path.join(configuredDir, "trufflehog");

  const storeDir = options.storeDir ?? getTrufflehogStoreDirectory();
  const platform = resolveSupportedPlatform();
  const { buildId, build } = await resolveManagedBuild(storeDir, platform);
  return await installManagedBinary(storeDir, buildId, build, options.log);
}

export async function getTrufflehogStatus(
  options: Omit<EnsureTrufflehogOptions, "log"> = {},
): Promise<TrufflehogStatus> {
  const configuredPath = resolveConfiguredBinaryPath(options.binaryPath);
  const configuredDir = resolveConfiguredDirectory();
  const storeDir = options.storeDir ?? getTrufflehogStoreDirectory();
  const platform = resolveSupportedPlatform();
  const { ref, buildId, build } = await resolveManagedBuild(storeDir, platform);
  const managedPath = installedBinaryPath(storeDir, buildId);
  return {
    ref,
    version: build.version,
    platform,
    configuredPath,
    configuredDir,
    managedPath,
    installed: fs.existsSync(managedPath),
    downloadUrl: build.url,
    buildId,
  };
}

export const __test = {
  resolveSupportedPlatform,
  installedBinaryPath,
  installedSourcePath,
  parseBuiltinTrufflehogRegistry,
};
