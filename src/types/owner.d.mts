import type { JsonValue, NativePaths } from './json.d.mts'
export type ContinuityState = 'retained' | 'blocked' | 'registration_required' | 'recovery_available' | 'reregistration_required'
export interface Continuity { state: ContinuityState; action: 'none' | 'register' | 'rebind' | 'reregister' | 'review_conflict' | 'restore_exact_release'; reason: string }
export interface RegistrationChallenge {
 registrationRef: string; challenge: string; rpId: 'localhost'; origin: string
 timeout: number; expiresAtUnixMs: number; userHandle: string | null; credentialId: string | null
}
export interface AuthenticationChallenge {
 authenticationRef: string; challenge: string; rpId: 'localhost'; origin: string
 timeout: number; expiresAtUnixMs: number; credentialId: string
}
export interface OwnerProjection {
 schema: 'crowsi://browser-security/owner/v1'
 state: 'ready' | 'passkey-registration-required' | 'foundation-required'
 passkeyRegistered: boolean; passkeyUsable: boolean
 checks: { id: string; available: boolean }[]
 continuity: Continuity
 recovery: { providerAvailable: boolean; rootRegistered: boolean; continuity: Continuity }
 registration: RegistrationChallenge | null
}
export interface RegistrationResponse {
 registrationRef: string; credentialId: string; clientDataJSON: string
 authenticatorData: string; publicKeySpki: string
}
export interface AssertionResponse {
 credentialId: string; clientDataJSON: string; authenticatorData: string; signature: string
}
export interface OwnerOptions {
 origin: string
 paths?: NativePaths
 run?: (executable: string, args: string[], input?: string | Uint8Array) => Promise<JsonValue>
 onDiagnostic?: (value: { code: string; phase: string }) => void
}
