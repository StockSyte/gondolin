import os from "os";
import path from "path";

export function cacheBaseDir(): string {
  return process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
}

export function gondolinCacheDir(...paths: string[]): string {
  return path.join(cacheBaseDir(), "gondolin", ...paths);
}
