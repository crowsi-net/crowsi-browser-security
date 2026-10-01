export interface BrowserAccessSession {
  authenticated: true
  csrf: string
  expiresAtUnixMs: number
}
export function consumeLaunchCredential(browser?: Window): string | null
export function clearLaunchCredential(browser?: Window): void
export function connectBrowser(options: {
  request: (path: string, options: { timeout: number; method?: 'POST'; body?: { credential: string } }) => Promise<unknown>
  credential: string | null
  probePath?: string
  connectPath?: string
}): Promise<BrowserAccessSession>
