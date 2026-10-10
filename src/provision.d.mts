import type { JsonValue } from './types/json.d.mts'
export interface CustodyRuntime {
 schema: 'crowsi://platform-custody/runtime/v1'
 kind: 'windows-dpapi-user'
 namespace: string
 helper_path: string
 helper_sha256: string
 protocol_version: 'crowsi-windows-custody-v1'
}
export function initializeSecurityRoot(root: string): void
export function custodyRuntime(executable: string, digest: string, namespace: string): CustodyRuntime
export function installPrivateJson(path: string, value: JsonValue, overwrite?: boolean): void
export function installPrivateExecutable(source: string, target: string): { executable: string; digest: string }
export function ownerFile(path: string, maximum?: number, executable?: boolean): boolean
/** Requires private permissions, a regular unshared inode and no symbolic link. */
export function readPrivateJson(path: string, maximum?: number): JsonValue
