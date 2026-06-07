import fs from "fs";
import path from "path";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";

import { ensureTrufflehogBinary, ensureTrufflehogSourceDir } from "./trufflehog.ts";

const MAX_TEXT_FILE_BYTES = 1024 * 1024;
const SCAN_SKIP_NAMES = new Set([".git", "node_modules", "dist", ".cache"]);
const HOSTNAME_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
const URL_RE = /https?:\/\/[^\s"'`<>]+/gi;
const DETECTOR_SOURCE_SKIP_FILE_RE = /(?:^|\/)(?:[^/]+_test|[^/]+_integration_test)\.go$/;
const trufflehogScanCache = new Map<string, Promise<TrufflehogScanResult>>();

type TrufflehogScanResult = {
  ok: boolean;
  stdout: string;
  stderr: string;
};

type TrufflehogFinding = {
  DetectorName?: string;
  DetectorDescription?: string;
  Verified?: boolean;
  ExtraData?: Record<string, string>;
};

export type SecretHostSuggestion = {
  /** suggested host name */
  host: string;
  /** evidence file path relative to the scan root */
  file: string;
  /** evidence line number */
  line: number;
  /** one-line evidence snippet */
  snippet: string;
  /** evidence hit count for this host */
  count: number;
};

export type SuggestSecretHostsOptions = {
  /** secret env var name */
  secretName: string;
  /** secret value to search for */
  secretValue: string;
  /** repository or workspace path to scan */
  cwd: string;
};

async function runTrufflehogScan(cwd: string): Promise<TrufflehogScanResult> {
  const cached = trufflehogScanCache.get(cwd);
  if (cached) {
    return await cached;
  }

  const promise = (async () => {
    const gitDir = path.join(cwd, ".git");
    const isGitRepo = fs.existsSync(gitDir);
    const args = isGitRepo
      ? [
          "git",
          pathToFileURL(cwd).href,
          "--json",
          "--no-update",
          "--results=verified,unknown,unverified",
        ]
      : [
          "filesystem",
          cwd,
          "--json",
          "--no-update",
          "--results=verified,unknown,unverified",
        ];

    const binaryPath = await ensureTrufflehogBinary();

    return await new Promise<TrufflehogScanResult>((resolve, reject) => {
      const child = spawn(binaryPath, args, {
        cwd,
        stdio: ["ignore", "pipe", "pipe"],
      });

      let stdout = "";
      let stderr = "";

      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.on("error", (error) => {
        reject(error);
      });
      child.on("close", (code) => {
        if (code === 0 || code === 183) {
          resolve({ ok: true, stdout, stderr });
          return;
        }
        reject(
          new Error(
            `trufflehog scan failed with exit code ${code ?? "unknown"}${stderr ? `: ${stderr.trim()}` : ""}`,
          ),
        );
      });
    });
  })();

  trufflehogScanCache.set(cwd, promise);
  try {
    return await promise;
  } catch (error) {
    trufflehogScanCache.delete(cwd);
    throw error;
  }
}

function isProbablyText(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 1024));
  for (const byte of sample) {
    if (byte === 0) return false;
  }
  return true;
}

function walkFiles(root: string): string[] {
  const files: string[] = [];
  const stack = [root];

  while (stack.length > 0) {
    const current = stack.pop()!;
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      if (SCAN_SKIP_NAMES.has(entry.name)) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile()) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

function extractUrlHosts(snippet: string): string[] {
  const hosts = new Set<string>();

  for (const match of snippet.matchAll(URL_RE)) {
    try {
      const hostname = new URL(match[0]).hostname.toLowerCase();
      if (hostname) hosts.add(hostname);
    } catch {
      // ignore invalid urls
    }
  }

  return [...hosts];
}

function extractHosts(snippet: string): string[] {
  const hosts = new Set<string>(extractUrlHosts(snippet));

  for (const match of snippet.matchAll(HOSTNAME_RE)) {
    const hostname = match[0].toLowerCase();
    if (hostname) hosts.add(hostname);
  }

  return [...hosts];
}

function collectSuggestionsFromFile(
  root: string,
  filePath: string,
  secretValue: string,
): SecretHostSuggestion[] {
  const stat = fs.statSync(filePath);
  if (stat.size === 0 || stat.size > MAX_TEXT_FILE_BYTES) {
    return [];
  }

  const buffer = fs.readFileSync(filePath);
  if (!isProbablyText(buffer)) {
    return [];
  }

  const content = buffer.toString("utf8");
  if (!content.includes(secretValue)) {
    return [];
  }

  const lines = content.split(/\r?\n/);
  const suggestions: SecretHostSuggestion[] = [];

  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes(secretValue)) continue;
    const start = Math.max(0, i - 2);
    const end = Math.min(lines.length, i + 3);
    const snippet = lines.slice(start, end).join(" ").trim();
    const hosts = extractHosts(snippet);
    for (const host of hosts) {
      suggestions.push({
        host,
        file: path.relative(root, filePath) || path.basename(filePath),
        line: i + 1,
        snippet: lines[i].trim().slice(0, 160),
        count: 1,
      });
    }
  }

  return suggestions;
}

function parseTrufflehogJsonLines(stdout: string): TrufflehogFinding[] {
  const findings: TrufflehogFinding[] = [];

  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      findings.push(JSON.parse(trimmed) as TrufflehogFinding);
    } catch {
      // ignore non-json lines
    }
  }

  return findings;
}

async function runTrufflehogSecretDetection(
  secretValue: string,
): Promise<TrufflehogFinding[]> {
  const binaryPath = await ensureTrufflehogBinary();
  const tmpRoot = fs.mkdtempSync(path.join(process.env.TMPDIR ?? "/tmp", "gondolin-secret-detect-"));
  const filePath = path.join(tmpRoot, "secret.txt");

  try {
    fs.writeFileSync(filePath, `${secretValue}\n`, { mode: 0o600 });
    const result = await new Promise<TrufflehogScanResult>((resolve, reject) => {
      const child = spawn(
        binaryPath,
        [
          "filesystem",
          filePath,
          "--json",
          "--no-update",
          "--no-verification",
          "--results=verified,unknown,unverified",
        ],
        {
          cwd: tmpRoot,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );

      let stdout = "";
      let stderr = "";
      child.stdout.setEncoding("utf8");
      child.stderr.setEncoding("utf8");
      child.stdout.on("data", (chunk: string) => {
        stdout += chunk;
      });
      child.stderr.on("data", (chunk: string) => {
        stderr += chunk;
      });
      child.on("error", reject);
      child.on("close", (code) => {
        if (code === 0 || code === 183) {
          resolve({ ok: true, stdout, stderr });
          return;
        }
        reject(
          new Error(
            `trufflehog secret detection failed with exit code ${code ?? "unknown"}${stderr ? `: ${stderr.trim()}` : ""}`,
          ),
        );
      });
    });

    return parseTrufflehogJsonLines(result.stdout);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
}

function collectDetectorSourceFiles(
  detectorsDir: string,
  detectorName: string,
): string[] {
  const files: string[] = [];
  const needle = `DetectorType_${detectorName}`;
  const stack = [detectorsDir];

  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".go")) continue;
      const content = fs.readFileSync(fullPath, "utf8");
      if (content.includes(needle)) {
        files.push(fullPath);
        const dir = path.dirname(fullPath);
        for (const sibling of fs.readdirSync(dir)) {
          const siblingPath = path.join(dir, sibling);
          if (
            siblingPath !== fullPath &&
            sibling.endsWith(".go") &&
            fs.statSync(siblingPath).isFile()
          ) {
            files.push(siblingPath);
          }
        }
      }
    }
  }

  return [...new Set(files)];
}

function normalizeSuggestedHost(host: string): string | null {
  const trimmed = host.trim().toLowerCase();
  if (!trimmed) return null;
  if (trimmed === "localhost") return null;
  if (!trimmed.includes(".")) return null;
  return trimmed;
}

function collectSuggestionsFromDetectorSource(
  sourceRoot: string,
  detectorName: string,
): SecretHostSuggestion[] {
  const detectorsDir = path.join(sourceRoot, "pkg", "detectors");
  if (!fs.existsSync(detectorsDir)) {
    return [];
  }

  const sourceFiles = collectDetectorSourceFiles(detectorsDir, detectorName);
  const suggestions: SecretHostSuggestion[] = [];

  for (const filePath of sourceFiles) {
    if (DETECTOR_SOURCE_SKIP_FILE_RE.test(filePath)) {
      continue;
    }

    const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const hosts = extractUrlHosts(lines[i]);
      for (const host of hosts) {
        const normalized = normalizeSuggestedHost(host);
        if (!normalized) continue;
        suggestions.push({
          host: normalized,
          file: path.relative(sourceRoot, filePath),
          line: i + 1,
          snippet: lines[i].trim().slice(0, 160),
          count: 1,
        });
      }
    }
  }

  return suggestions;
}

function mergeSuggestions(
  suggestions: SecretHostSuggestion[],
): SecretHostSuggestion[] {
  const merged = new Map<string, SecretHostSuggestion>();

  for (const suggestion of suggestions) {
    const existing = merged.get(suggestion.host);
    if (!existing) {
      merged.set(suggestion.host, suggestion);
      continue;
    }
    existing.count += suggestion.count;
  }

  return [...merged.values()].sort(
    (a, b) => b.count - a.count || a.host.localeCompare(b.host),
  );
}

export async function suggestHostsForSecret(
  options: SuggestSecretHostsOptions,
): Promise<SecretHostSuggestion[]> {
  if (!options.secretValue) {
    return [];
  }

  const findings = await runTrufflehogSecretDetection(options.secretValue);
  const detectorSuggestions: SecretHostSuggestion[] = [];

  if (findings.length > 0) {
    const sourceRoot = await ensureTrufflehogSourceDir();
    for (const finding of findings) {
      if (!finding.DetectorName) continue;
      detectorSuggestions.push(
        ...collectSuggestionsFromDetectorSource(
          sourceRoot,
          finding.DetectorName,
        ),
      );
      for (const value of Object.values(finding.ExtraData ?? {})) {
        for (const host of extractUrlHosts(value)) {
          const normalized = normalizeSuggestedHost(host);
          if (!normalized) continue;
          detectorSuggestions.push({
            host: normalized,
            file: `detector:${finding.DetectorName}`,
            line: 0,
            snippet: value.slice(0, 160),
            count: 1,
          });
        }
      }
    }
  }

  if (detectorSuggestions.length > 0) {
    return mergeSuggestions(detectorSuggestions);
  }

  await runTrufflehogScan(options.cwd);

  const repoSuggestions = walkFiles(options.cwd).flatMap((filePath) =>
    collectSuggestionsFromFile(options.cwd, filePath, options.secretValue),
  );

  return mergeSuggestions(repoSuggestions);
}

export const __test = {
  extractHosts,
  extractUrlHosts,
  parseTrufflehogJsonLines,
  collectSuggestionsFromFile,
  collectSuggestionsFromDetectorSource,
  mergeSuggestions,
};
