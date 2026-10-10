/** JSON values returned by an explicitly supplied native authority. */
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }
export interface NativePaths {
 securityRoot?: string
 paAgent?: string
 credentialAgent?: string
 ownerRecoveryProvider?: string
}
