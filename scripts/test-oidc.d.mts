import type { ChildProcess } from "node:child_process";

export function stopTestProcess(proc: ChildProcess): Promise<void>;
export function startTestOIDC(options: {
  binary: string;
  dataDir: string;
  base: string;
  name?: string;
}): Promise<{ env: Record<string, string>; stop: () => Promise<void> }>;
export function loginTestAdmin(base: string): Promise<string>;
