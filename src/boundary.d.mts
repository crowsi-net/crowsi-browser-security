export interface OwnerOrigin { readonly origin: string; readonly host: string; readonly port: string; readonly protocol: string }
export interface RequestBoundary {
 host?: string
 origin?: string
 fetchSite?: string
 method: string
}
export function parseOwnerOrigin(value: string): Readonly<OwnerOrigin>
export function assessRequestBoundary(owner: OwnerOrigin, request: RequestBoundary): string | null
export function securityHeaders(options?: { scriptNonce?: string; styleNonce?: string }): Readonly<Record<string, string>>
