import { createHash, randomUUID } from "crypto";
import fs from "fs";
import path from "path";

export { cacheBaseDir } from "../cache.ts";

export function normalizeSha256(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error(`invalid ${label}: expected sha256 hex string`);
  }
  return value.toLowerCase();
}

export function computeFileHash(filePath: string): string {
  const hash = createHash("sha256");
  const fd = fs.openSync(filePath, "r");
  const buffer = Buffer.allocUnsafe(1024 * 1024);

  try {
    let bytesRead = 0;
    while ((bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) {
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }

  return hash.digest("hex");
}

export async function downloadToBuffer(
  url: string,
  expectedSha256: string | undefined,
  userAgent: string,
  options: {
    downloadLabel?: string;
    checksumLabel?: string;
  } = {},
): Promise<Buffer> {
  const response = await fetch(url, {
    headers: { "User-Agent": userAgent },
  });
  if (!response.ok) {
    if (options.downloadLabel) {
      throw new Error(
        `failed to download ${options.downloadLabel}: ${response.status} ${response.statusText} (${url})`,
      );
    }
    throw new Error(
      `failed to download ${url}: ${response.status} ${response.statusText}`,
    );
  }

  const data = Buffer.from(await response.arrayBuffer());
  if (expectedSha256) {
    const hash = createHash("sha256").update(data).digest("hex");
    if (hash !== expectedSha256.toLowerCase()) {
      if (options.checksumLabel) {
        throw new Error(
          `${options.checksumLabel} checksum mismatch for ${url}\n  expected: ${expectedSha256}\n  got:      ${hash}`,
        );
      }
      throw new Error(
        `downloaded checksum mismatch for ${url}\n  expected: ${expectedSha256}\n  got:      ${hash}`,
      );
    }
  }
  return data;
}

type RegistryCache<T> = {
  /** source registry URL */
  url: string;
  /** HTTP etag from the last successful fetch */
  etag?: string;
  /** cached registry payload */
  registry: T;
};

function loadRegistryCache<T>(
  url: string,
  storeDir: string,
  cacheFileName: string,
  parse: (raw: unknown, sourceUrl: string) => T,
): RegistryCache<T> | null {
  const cachePath = path.join(storeDir, cacheFileName);
  if (!fs.existsSync(cachePath)) return null;

  try {
    const parsed = JSON.parse(fs.readFileSync(cachePath, "utf8")) as RegistryCache<T>;
    if (!parsed || typeof parsed !== "object") return null;
    if (parsed.url !== url) return null;
    return {
      url,
      etag: typeof parsed.etag === "string" ? parsed.etag : undefined,
      registry: parse(parsed.registry as unknown, url),
    };
  } catch {
    return null;
  }
}

function saveRegistryCache<T>(
  cache: RegistryCache<T>,
  storeDir: string,
  cacheFileName: string,
): void {
  fs.mkdirSync(storeDir, { recursive: true });
  const cachePath = path.join(storeDir, cacheFileName);
  const tmpPath = `${cachePath}.tmp-${randomUUID().slice(0, 8)}`;
  fs.writeFileSync(tmpPath, JSON.stringify(cache, null, 2));
  fs.renameSync(tmpPath, cachePath);
}

export async function fetchCachedJsonRegistry<T>(options: {
  url: string;
  storeDir: string;
  cacheFileName: string;
  userAgent: string;
  parse: (raw: unknown, sourceUrl: string) => T;
  label: string;
}): Promise<T> {
  const cached = loadRegistryCache(
    options.url,
    options.storeDir,
    options.cacheFileName,
    options.parse,
  );

  const headers: Record<string, string> = {
    "User-Agent": options.userAgent,
  };
  if (cached?.etag) {
    headers["If-None-Match"] = cached.etag;
  }

  let response: Response;
  try {
    response = await fetch(options.url, { headers });
  } catch (error) {
    if (cached) return cached.registry;
    throw new Error(
      `failed to fetch ${options.label} from ${options.url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (response.status === 304 && cached) {
    return cached.registry;
  }
  if (!response.ok) {
    if (cached) return cached.registry;
    throw new Error(
      `failed to fetch ${options.label}: ${response.status} ${response.statusText} (${options.url})`,
    );
  }

  const text = await response.text();
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new Error(
      `failed to parse ${options.label} json from ${options.url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const registry = options.parse(raw, options.url);
  saveRegistryCache(
    {
      url: options.url,
      etag: response.headers.get("etag") ?? undefined,
      registry,
    },
    options.storeDir,
    options.cacheFileName,
  );
  return registry;
}
