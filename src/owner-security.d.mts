import type { OwnerOptions, OwnerProjection, RegistrationResponse, AssertionResponse, AuthenticationChallenge } from './types/owner.d.mts'
export type * from './types/owner.d.mts'
/** Coordinates ceremonies; native providers retain authority and secret material. */
export class OwnerSecurity {
 constructor(options: OwnerOptions)
 projection(): OwnerProjection
 inspect(): Promise<OwnerProjection>
 start(): Promise<OwnerProjection>
 stage(value: RegistrationResponse): Promise<OwnerProjection>
 confirm(value: AssertionResponse & { registrationRef: string }): Promise<OwnerProjection>
 startAuthentication(): Promise<AuthenticationChallenge>
 confirmAuthentication(value: AssertionResponse & { authenticationRef: string }): Promise<true>
 startRebind(): Promise<AuthenticationChallenge>
 confirmRebind(value: AssertionResponse & { authenticationRef: string }): Promise<OwnerProjection>
 resetInvalidRegistration(): Promise<OwnerProjection>
 cancel(reference: string): void
 close(): void
}
