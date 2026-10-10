import type { NativePaths } from '../src/types/json.d.mts'
/** Starts a loopback demonstration only on explicit invocation. */
export function startDemo(options?: { port?: number; paths?: NativePaths }): Promise<{ url: string; close(): Promise<void> }>
