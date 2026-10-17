import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, before, test } from 'node:test'
import { promisify } from 'node:util'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { Miniflare, Request as MiniflareRequest, Response as MiniflareResponse } from 'miniflare'

const origin = 'https://uoftauth.boratto.ca'
const tenant = '78aac226-2f03-4b4d-9037-b46d56c55210'
const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`
const oid = '00000000-0000-4000-8000-000000000001'
const clientId = 'test-only-microsoft-client-id'
const callback = `${origin}/auth/callback/microsoft-entra-id`
const keys = await generateKeyPair('RS256')
const jwk = { ...await exportJWK(keys.publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' }
let bundle: string

before(async () => {
  bundle = await mkdtemp(join(tmpdir(), 'uoftauth-oauth-'))
  await promisify(execFile)('npx', ['wrangler', 'deploy', '--dry-run', '--outdir', bundle], {
    cwd: new URL('..', import.meta.url),
  })
})

after(async () => {
  await rm(bundle, { recursive: true })
})

type Scenario = { userType?: 'Member' | 'Guest'; tid?: string; nonce?: string; state?: string; viewOtherConsent?: boolean }

async function login(scenario: Scenario = {}) {
  const cookies = new Map<string, string>()
  const requests: string[] = []
  let authorization: URL
  const runtime = new Miniflare({
    modules: true,
    modulesRoot: bundle,
    scriptPath: join(bundle, 'index.js'),
    compatibilityDate: '2026-07-30',
    bindings: {
      AUTH_SECRET: 'test-only-session-secret-at-least-thirty-two-characters',
      AUTH_MICROSOFT_ENTRA_ID_ID: clientId,
      AUTH_MICROSOFT_ENTRA_ID_SECRET: 'test-only-microsoft-secret',
    },
    async outboundService(request: MiniflareRequest) {
      const url = new URL(request.url)
      requests.push(url.pathname)
      if (url.pathname.endsWith('/.well-known/openid-configuration')) {
        return MiniflareResponse.json({
          issuer,
          authorization_endpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
          token_endpoint: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
          userinfo_endpoint: 'https://graph.microsoft.com/oidc/userinfo',
          jwks_uri: `https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`,
          response_types_supported: ['code'],
          subject_types_supported: ['pairwise'],
          id_token_signing_alg_values_supported: ['RS256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          code_challenge_methods_supported: ['S256'],
        })
      }
      if (url.pathname.endsWith('/discovery/v2.0/keys')) return MiniflareResponse.json({ keys: [jwk] })
      if (url.pathname.endsWith('/oauth2/v2.0/token')) {
        const body = new URLSearchParams(await request.text())
        assert.equal(body.get('grant_type'), 'authorization_code')
        assert.equal(body.get('code'), 'test-authorization-code')
        assert.equal(body.get('redirect_uri'), callback)
        assert.equal(
          createHash('sha256').update(body.get('code_verifier')!).digest('base64url'),
          authorization.searchParams.get('code_challenge'),
        )
        const idToken = await new SignJWT({
          tid: scenario.tid ?? tenant,
          oid,
          name: 'test student',
          email: 'student@mail.utoronto.ca',
          nonce: scenario.nonce ?? authorization.searchParams.get('nonce'),
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
          .setIssuer(issuer)
          .setAudience(clientId)
          .setSubject('test-pairwise-subject')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(keys.privateKey)
        return MiniflareResponse.json({ access_token: 'test-access-token', token_type: 'Bearer', expires_in: 3600, id_token: idToken })
      }
      if (url.origin === 'https://graph.microsoft.com' && url.pathname === '/v1.0/me') {
        assert.equal(url.searchParams.get('$select'), 'id,userType')
        assert.equal(request.headers.get('authorization'), 'Bearer test-access-token')
        return MiniflareResponse.json({ id: oid, userType: scenario.userType ?? 'Member' })
      }
      throw new Error(`unexpected upstream request: ${request.url}`)
    },
  })

  async function request(path: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) {
    const response = await runtime.dispatchFetch(`${origin}${path}`, {
      ...init,
      headers: { Cookie: [...cookies.values()].join('; '), ...init.headers },
      redirect: 'manual',
    })
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(';', 1)[0]
      cookies.set(pair.slice(0, pair.indexOf('=')), pair)
    }
    return response
  }

  try {
    const consent = await request('/login?domain=muoft.ca')
    assert.equal(consent.status, 200)
    const html = await consent.text()
    const csrfToken = html.match(/name="csrfToken" value="([^"]+)"/)![1]
    const callbackUrl = html.match(/name="callbackUrl" value="([^"]+)"/)![1]
    const intent = html.match(/name="intent" value="([^"]+)"/)![1]
    assert.equal(callbackUrl, 'https://muoft.ca/')
    assert.equal(cookies.has('__Host-uoftauth.login'), false)
    const signin = await request('/auth/signin/microsoft-entra-id', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: origin },
      body: new URLSearchParams({ csrfToken, callbackUrl, intent }).toString(),
    })
    assert.equal(signin.status, 302)
    authorization = new URL(signin.headers.get('location')!)
    assert.equal(authorization.origin, 'https://login.microsoftonline.com')
    assert.equal(authorization.pathname, `/${tenant}/oauth2/v2.0/authorize`)
    assert.equal(authorization.searchParams.get('client_id'), clientId)
    assert.equal(authorization.searchParams.get('redirect_uri'), callback)
    assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256')
    assert.ok(authorization.searchParams.get('state'))
    assert.ok(authorization.searchParams.get('nonce'))
    assert.ok(cookies.has('__Host-uoftauth.login'))

    if (scenario.viewOtherConsent) {
      const acceptedIntent = cookies.get('__Host-uoftauth.login')
      const otherConsent = await request('/login?domain=attacker.example')
      assert.equal(otherConsent.status, 200)
      assert.equal(cookies.get('__Host-uoftauth.login'), acceptedIntent)
    }

    const params = new URLSearchParams({
      code: 'test-authorization-code',
      state: scenario.state ?? authorization.searchParams.get('state')!,
    })
    const callbackResponse = await request(`/auth/callback/microsoft-entra-id?${params}`)
    assert.equal(callbackResponse.status, 302, await callbackResponse.clone().text())
    const me = await request('/me', { headers: { Origin: 'https://muoft.ca' } })
    const otherSite = await request('/me', { headers: { Origin: 'https://attacker.example' } })
    return {
      status: me.status,
      user: await me.json(),
      otherSiteUser: await otherSite.json(),
      cors: me.headers.get('access-control-allow-origin'),
      redirect: callbackResponse.headers.get('location'),
      sessionCookie: callbackResponse.headers.getSetCookie().find(value => value.startsWith('__Secure-authjs.session-token=')),
      clearedIntent: callbackResponse.headers.getSetCookie().find(value => value.startsWith('__Host-uoftauth.login=')),
      requests,
    }
  } finally {
    await runtime.dispose()
  }
}

test('microsoft member signs in through the callback and receives /me identity', async () => {
  const result = await login()
  assert.equal(result.redirect, 'https://muoft.ca/')
  assert.equal(result.status, 200)
  assert.deepEqual(result.user, { id: `${tenant}:${oid}`, name: 'test student', email: 'student@mail.utoronto.ca' })
  assert.equal(result.otherSiteUser, null)
  assert.equal(result.cors, 'https://muoft.ca')
  assert.match(result.sessionCookie!, /; HttpOnly/i)
  assert.match(result.sessionCookie!, /; Secure/i)
  assert.match(result.sessionCookie!, /; SameSite=None/i)
  assert.match(result.clearedIntent!, /; Max-Age=0/i)
  assert.ok(result.requests.includes('/v1.0/me'))
})

test('viewing another domain consent page does not change the accepted login grant', async () => {
  const result = await login({ viewOtherConsent: true })
  assert.equal(result.redirect, 'https://muoft.ca/')
  assert.deepEqual(result.user, { id: `${tenant}:${oid}`, name: 'test student', email: 'student@mail.utoronto.ca' })
  assert.equal(result.otherSiteUser, null)
})

for (const [name, scenario] of [
  ['guest account', { userType: 'Guest' }],
  ['different tenant', { tid: '00000000-0000-4000-8000-000000000002' }],
  ['wrong nonce', { nonce: 'wrong-nonce' }],
  ['wrong state', { state: 'wrong-state' }],
] as const) {
  test(`microsoft callback rejects ${name}`, async () => {
    const result = await login(scenario)
    assert.equal(result.status, 200)
    assert.equal(result.user, null)
    assert.equal(result.sessionCookie, undefined)
    assert.notEqual(result.redirect, 'https://muoft.ca/')
  })
}
