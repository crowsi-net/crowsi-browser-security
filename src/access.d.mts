export interface Session { sessionId: string; csrfToken: string; expiresAt: number }
export interface SessionState { csrfToken: string; expiresAt: number; nonces: Set<string> }
export interface AuthorityOptions {
 launchToken?: string | null
 ttlMs?: number
 maxSessions?: number
 now?: () => number
 random?: (size: number) => Uint8Array
}
/** Creates a one-use local bootstrap URL; the fragment is never sent by HTTP. */
export function createLaunchAccess(origin: string): Readonly<{ credential: string; url: string }>
export class SessionAuthority {
 constructor(options?: AuthorityOptions)
 launchToken: string | null
 readonly maxSessions: number
 readonly ttlMs: number
 readonly sessions: Map<string, SessionState>
 launch(token: string): Session
 issue(): Session
 authenticate(sessionId: string): SessionState
 authorizeMutation(sessionId: string, csrfToken: string, nonce: string): void
 revoke(sessionId: string): void
}
