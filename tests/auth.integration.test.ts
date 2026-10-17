import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { after, before, test } from 'node:test'
import { promisify } from 'node:util'
import { decode, encode } from '@auth/core/jwt'
import { Miniflare } from 'miniflare'

const origin = 'https://uoftauth.example'
const frontend = 'https://frontend.example'
const cookieName = '__Secure-authjs.session-token'
const intentName = '__Host-uoftauth.login'
const env = {
    AUTH_SECRET: 'test-only-secret-with-at-least-thirty-two-characters',
    AUTH_MICROSOFT_ENTRA_ID_ID: 'test-client-id',
    AUTH_MICROSOFT_ENTRA_ID_SECRET: 'test-client-secret'
}
const user = {
    id: '78aac226-2f03-4b4d-9037-b46d56c55210:test-student',
    name: 'test student',
    email: 'student@mail.utoronto.ca'
}
let directory: string
let runtime: Miniflare
type WorkerResponse = Awaited<ReturnType<Miniflare['dispatchFetch']>>

// Synthetic sessions test the bundled worker, not Microsoft's login or Graph.
async function session(secret = env.AUTH_SECRET, maxAge = 3600, email: string | null = user.email) {
    const token = await encode({
        token: { sub: user.id, name: user.name, email, origin: frontend },
        secret, salt: cookieName, maxAge
    })
    return `${cookieName}=${token}`
}

function assertCors(response: WorkerResponse, client = frontend) {
    assert.equal(response.headers.get('access-control-allow-origin'), client)
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true')
    assert.match(response.headers.get('vary')!, /(?:^|,\s*)Origin(?:,|$)/i)
    assert.equal(response.headers.get('cache-control'), 'no-store')
}

function storeCookies(response: WorkerResponse, jar: Map<string, string>) {
    for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(';', 1)[0]
        const index = pair.indexOf('=')
        jar.set(pair.slice(0, index), pair.slice(index + 1))
    }
}

before(async () => {
    directory = await mkdtemp(join(tmpdir(), 'uoftauth-test-'))
    await promisify(execFile)(process.execPath, [
        resolve('node_modules/wrangler/bin/wrangler.js'),
        'deploy', '--dry-run', '--outdir', directory
    ], { env: { ...process.env, WRANGLER_SEND_METRICS: 'false' } })
    runtime = new Miniflare({
        modules: true, modulesRoot: directory, scriptPath: join(directory, 'index.js'),
        compatibilityDate: '2026-07-30', bindings: env
    })
})

after(async () => {
    await runtime.dispose()
    await rm(directory, { recursive: true })
})

test('anonymous, forged, and expired sessions return null with credentialed CORS', async () => {
    for (const cookie of ['', await session('wrong-test-secret'), await session(env.AUTH_SECRET, -60)]) {
        const response = await runtime.dispatchFetch(`${origin}/me`, {
            headers: { Origin: frontend, Cookie: cookie }
        })
        assert.equal(response.status, 200)
        assert.deepEqual(await response.json(), null)
        assertCors(response)
    }
})

test('a valid session returns only its user and forwards the renewed secure cookie', async () => {
    const response = await runtime.dispatchFetch(`${origin}/me`, {
        headers: { Origin: frontend, Cookie: await session() }
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), user)
    assertCors(response)
    const renewed = response.headers.getSetCookie().find(cookie => cookie.startsWith(`${cookieName}=`))!
    assert.match(renewed, /; HttpOnly/i)
    assert.match(renewed, /; Secure/i)
    assert.match(renewed, /; SameSite=None/i)
    const reread = await runtime.dispatchFetch(`${origin}/me`, { headers: { Cookie: renewed.split(';', 1)[0] } })
    assert.deepEqual(await reread.json(), user)
})

test('email is nullable and non-browser requests do not require an Origin header', async () => {
    const response = await runtime.dispatchFetch(`${origin}/me`, {
        headers: { Cookie: await session(env.AUTH_SECRET, 3600, null) }
    })
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { ...user, email: null })
    assert.equal(response.headers.get('access-control-allow-origin'), null)
})

test('a session does not reveal its account to another frontend or the www variant', async () => {
    for (const client of ['https://other.example', 'https://www.frontend.example', `${frontend}.attacker.example`]) {
        const response = await runtime.dispatchFetch(`${origin}/me`, {
            headers: { Origin: client, Cookie: await session() }
        })
        assert.equal(response.status, 200)
        assert.deepEqual(await response.json(), null)
        assertCors(response, client)
    }
})

test('session preflight permits GET and rejects other methods', async () => {
    const response = await runtime.dispatchFetch(`${origin}/me`, {
        method: 'OPTIONS', headers: { Origin: frontend, 'Access-Control-Request-Method': 'GET' }
    })
    assert.equal(response.status, 204)
    assert.equal(response.headers.get('access-control-allow-methods'), 'GET')
    assertCors(response)
    const rejected = await runtime.dispatchFetch(`${origin}/me`, {
        method: 'OPTIONS', headers: { Origin: frontend, 'Access-Control-Request-Method': 'POST' }
    })
    assert.equal(rejected.status, 405)
    assertCors(rejected)
    const post = await runtime.dispatchFetch(`${origin}/me`, { method: 'POST', headers: { Origin: frontend } })
    assert.equal(post.status, 405)
    assertCors(post)
})

test('login shows the chosen origin and binds it in a fifteen-minute encrypted intent', async () => {
    for (const domain of ['frontend.example', 'https://frontend.example', 'http://localhost:5173']) {
        const client = domain.includes('://') ? domain : `https://${domain}`
        const response = await runtime.dispatchFetch(`${origin}/login?${new URLSearchParams({ domain })}`)
        assert.equal(response.status, 200)
        const html = await response.text()
        assert.ok(html.includes(`<strong>${client}</strong>`))
        assert.match(html, /action="\/auth\/signin\/microsoft-entra-id"/)
        assert.match(html, /name="csrfToken" value="[^"]+"/)
        assert.ok(html.includes(`name="callbackUrl" value="${client}/"`))
        assert.equal(response.headers.get('access-control-allow-origin'), null)
        assert.equal(response.headers.getSetCookie().some(cookie => cookie.startsWith(`${intentName}=`)), false)
        const token = html.match(/name="intent" value="([^"]+)"/)![1]
        const intent = await decode({ token, secret: env.AUTH_SECRET, salt: intentName })
        assert.equal(intent!.origin, client)
        assert.equal(intent!.exp! - intent!.iat!, 900)
    }
})

test('only trusted muoft.ca origins auto-submit the signed signin form', async () => {
    for (const domain of ['muoft.ca', 'https://muoft.ca']) {
        const response = await runtime.dispatchFetch(`${origin}/login?${new URLSearchParams({ domain })}`)
        assert.equal(response.status, 200)
        const html = await response.text()
        const nonce = html.match(/<script nonce="([^"]+)">/)![1]
        assert.ok(response.headers.get('content-security-policy')!.includes(`'nonce-${nonce}'`))
        assert.match(html, /document\.forms\[0\]\.submit\(\)/)
        assert.match(html, /<form\b[^>]*\bhidden\b/)
        assert.match(html, /name="intent" value="[^"]+"/)
        assert.doesNotMatch(html, /<button|sign in to share/i)
    }
})

test('other domains, www, subdomains, and localhost retain manual consent', async () => {
    for (const domain of ['frontend.example', 'www.muoft.ca', 'sub.muoft.ca', 'muoft.ca.attacker.example', 'http://localhost:5173']) {
        const client = domain.includes('://') ? domain : `https://${domain}`
        const response = await runtime.dispatchFetch(`${origin}/login?${new URLSearchParams({ domain })}`)
        assert.equal(response.status, 200)
        const html = await response.text()
        assert.ok(html.includes(`<strong>${client}</strong>`))
        assert.match(html, /<button>sign in with uoft<\/button>/)
        assert.doesNotMatch(html, /<script/i)
    }
})

test('a failed-CSRF signin cannot replace the pending login intent', async () => {
    const consent = await runtime.dispatchFetch(`${origin}/login?domain=frontend.example`)
    const token = (await consent.text()).match(/name="intent" value="([^"]+)"/)![1]
    const rejected = await runtime.dispatchFetch(`${origin}/auth/signin/microsoft-entra-id`, {
        method: 'POST', redirect: 'manual',
        headers: { Origin: origin },
        body: new URLSearchParams({ intent: token, callbackUrl: `${frontend}/`, csrfToken: 'wrong-csrf' })
    })
    assert.equal(rejected.status, 302)
    assert.match(rejected.headers.get('location')!, /error=MissingCSRF/)
    assert.equal(rejected.headers.getSetCookie().some(cookie => cookie.startsWith(`${intentName}=`)), false)
})

test('login requires an explicit valid domain', async () => {
    for (const path of ['/login', '/login?domain=', '/login?domain=http%3A%2F%2Ffrontend.example', '/login?domain=ftp%3A%2F%2Ffrontend.example', '/login?domain=https%3A%2F%2F']) {
        assert.equal((await runtime.dispatchFetch(`${origin}${path}`)).status, 400, path)
    }
})

test('auth.js stores a validated return destination and rejects foreign Origin headers', async () => {
    const response = await runtime.dispatchFetch(`${origin}/auth/signin?${new URLSearchParams({ callbackUrl: `${frontend}/done` })}`)
    assert.equal(response.status, 200)
    const callback = response.headers.getSetCookie().find(cookie => cookie.startsWith('__Secure-authjs.callback-url='))!
    assert.equal(decodeURIComponent(callback.split(';', 1)[0].slice('__Secure-authjs.callback-url='.length)), `${origin}/me`)
    const denied = await runtime.dispatchFetch(`${origin}/auth/csrf`, { headers: { Origin: frontend } })
    assert.equal(denied.status, 403)
    assert.equal(denied.headers.get('access-control-allow-origin'), null)
})

test('auth.js signout requires CSRF and deletes the browser cookie', async () => {
    const jar = new Map([[cookieName, (await session()).slice(cookieName.length + 1)]])
    const header = () => Array.from(jar, ([key, value]) => `${key}=${value}`).join('; ')
    const rejected = await runtime.dispatchFetch(`${origin}/auth/signout`, {
        method: 'POST', redirect: 'manual', headers: { Cookie: header() },
        body: new URLSearchParams({ callbackUrl: `${origin}/me` })
    })
    assert.equal(rejected.status, 302)
    assert.match(rejected.headers.get('location')!, /error=MissingCSRF/)
    const before = await runtime.dispatchFetch(`${origin}/me`, { headers: { Cookie: header() } })
    assert.deepEqual(await before.json(), user)
    const csrf = await runtime.dispatchFetch(`${origin}/auth/csrf`, { headers: { Cookie: header() } })
    storeCookies(csrf, jar)
    const { csrfToken } = await csrf.json() as { csrfToken: string }
    const response = await runtime.dispatchFetch(`${origin}/auth/signout`, {
        method: 'POST', redirect: 'manual', headers: { Cookie: header() },
        body: new URLSearchParams({ csrfToken, callbackUrl: `${origin}/me` })
    })
    assert.equal(response.status, 302)
    assert.equal(response.headers.get('location'), `${origin}/me`)
    const deleted = response.headers.getSetCookie().find(cookie => cookie.startsWith(`${cookieName}=`))!
    assert.match(deleted, /Max-Age=0/i)
    storeCookies(response, jar)
    const after = await runtime.dispatchFetch(`${origin}/me`, { headers: { Cookie: header() } })
    assert.deepEqual(await after.json(), null)
})

test('root opens the account endpoint and unknown routes return 404', async () => {
    const response = await runtime.dispatchFetch(origin, { redirect: 'manual' })
    assert.equal(response.status, 302)
    assert.equal(new URL(response.headers.get('location')!, origin).pathname, '/me')
    assert.equal((await runtime.dispatchFetch(`${origin}/missing`)).status, 404)
})
