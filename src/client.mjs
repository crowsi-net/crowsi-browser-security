/** Browser-only bootstrap; applications never parse or persist URL credentials. */
export function consumeLaunchCredential(browser = globalThis.window) {
  const credential = new URLSearchParams(browser.location.hash.slice(1)).get('launch')
  clearLaunchCredential(browser)
  return credential
}

export function clearLaunchCredential(browser = globalThis.window) {
  if (browser.location.hash) browser.history.replaceState(null, '',
    `${browser.location.pathname}${browser.location.search}`)
}

export async function connectBrowser({ request, credential,
  probePath = '/api/session', connectPath = '/api/session/connect' }) {
  const existing = await request(probePath, { timeout: 15_000 })
  if (existing?.authenticated) return validSession(existing)
  if (!credential) throw new Error('crowsi-browser-security-session-unavailable')
  return validSession(await request(connectPath, { method: 'POST', body: { credential }, timeout: 15_000 }))
}

function validSession(value) {
  if (value?.authenticated !== true || typeof value.csrf !== 'string'
    || !/^[A-Za-z0-9_-]{43,128}$/u.test(value.csrf)
    || !Number.isSafeInteger(value.expiresAtUnixMs) || value.expiresAtUnixMs <= Date.now()) {
    throw new Error('crowsi-browser-security-session-response-invalid')
  }
  return value
}
