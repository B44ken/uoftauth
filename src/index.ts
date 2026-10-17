import { Auth, type AuthConfig } from '@auth/core'
import { decode, encode, getToken, type JWT } from '@auth/core/jwt'
import MicrosoftEntraID from '@auth/core/providers/microsoft-entra-id'
import { stringifySetCookie } from 'cookie'

const tenant = '78aac226-2f03-4b4d-9037-b46d56c55210'
const trustedOrigins = ['https://muoft.ca']

type Env = {
  AUTH_SECRET: string
  AUTH_MICROSOFT_ENTRA_ID_ID: string
  AUTH_MICROSOFT_ENTRA_ID_SECRET: string
}

const intentCookie = (url: URL) => `${url.protocol === 'https:' ? '__Host-' : ''}uoftauth.login`

async function config(request: Request, env: Env, url: URL, selectedIntent?: JWT): Promise<AuthConfig> {
  const secure = url.protocol === 'https:'
  const intent = selectedIntent ?? await getToken({ req: request, secret: env.AUTH_SECRET, cookieName: intentCookie(url) })
  return {
    basePath: '/auth',
    trustHost: true,
    secret: env.AUTH_SECRET,
    session: { strategy: 'jwt', maxAge: 3600 },
    cookies: {
      sessionToken: {
        name: `${secure ? '__Secure-' : ''}authjs.session-token`,
        options: { httpOnly: true, secure, sameSite: secure ? 'none' : 'lax', path: '/' },
      },
    },
    providers: [
      MicrosoftEntraID({
        name: 'uoft',
        clientId: env.AUTH_MICROSOFT_ENTRA_ID_ID,
        clientSecret: env.AUTH_MICROSOFT_ENTRA_ID_SECRET,
        issuer: `https://login.microsoftonline.com/${tenant}/v2.0`,
        authorization: { params: { scope: 'openid profile email User.Read' } },
        checks: ['pkce', 'state', 'nonce'],
        profile(profile) {
          return { id: `${profile.tid}:${profile.oid}`, name: profile.name, email: profile.email }
        },
      }),
    ],
    callbacks: {
      async signIn({ account, profile }) {
        if (!intent?.origin || profile?.tid !== tenant || !profile.oid) return false
        const response = await fetch('https://graph.microsoft.com/v1.0/me?$select=id,userType', {
          headers: { Authorization: `Bearer ${account!.access_token}` },
        })
        if (!response.ok) throw new Error(`microsoft graph: ${response.status}`)
        const user: { id: string; userType: string } = await response.json()
        return user.id === profile.oid && user.userType === 'Member'
      },
      jwt({ token, user, account }) {
        if (account) return { sub: account.providerAccountId, name: user.name, email: user.email, origin: intent!.origin }
        return token
      },
      session({ session, token }) {
        return {
          expires: session.expires,
          origin: token.origin,
          user: { id: token.sub!, name: token.name ?? null, email: token.email ?? null },
        }
      },
      redirect({ url: target, baseUrl }) {
        const destination = new URL(target, baseUrl)
        return destination.origin === baseUrl || destination.origin === intent?.origin
          ? destination.href : `${baseUrl}/me`
      },
    },
  }
}

async function route(request: Request, env: Env, url: URL): Promise<Response> {
  const origin = request.headers.get('Origin')
  if (url.pathname === '/me') {
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: request.headers.get('Access-Control-Request-Method') === 'GET' ? 204 : 405,
        headers: { 'Access-Control-Allow-Methods': 'GET' },
      })
    }
    if (request.method !== 'GET') return new Response('method not allowed', { status: 405 })
    const response = await Auth(new Request(new URL('/auth/session', url), request), await config(request, env, url))
    if (!response.ok) return response
    const session = await response.json() as { origin: string; user: unknown } | null
    const allowed = !origin || origin === url.origin || origin === session?.origin
    return Response.json(allowed ? session?.user ?? null : null, { headers: response.headers })
  }
  if (origin && origin !== url.origin) return new Response('origin not allowed', { status: 403 })
  if (url.pathname === '/login' && request.method === 'GET') {
    const domain = url.searchParams.get('domain')
    if (!domain) return new Response('use /login?domain=muoft.ca', { status: 400 })
    let client: URL
    try { client = new URL(domain.includes('://') ? domain : `https://${domain}`) }
    catch { return new Response('invalid domain', { status: 400 }) }
    if (client.protocol !== 'https:' && !(client.protocol === 'http:' && client.hostname === 'localhost')) {
      return new Response('domain must use https', { status: 400 })
    }
    const response = await Auth(new Request(new URL('/auth/csrf', url), request), await config(request, env, url))
    if (!response.ok) return response
    const { csrfToken } = await response.json() as { csrfToken: string }
    const token = await encode({ secret: env.AUTH_SECRET, salt: intentCookie(url), maxAge: 900, token: { origin: client.origin } })
    const trusted = trustedOrigins.includes(client.origin)
    const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    const page = new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>uoft login</title>
<body>${trusted ? '' : `<p>sign in to share your uoft account with <strong>${client.origin}</strong>.</p>`}
<form ${trusted ? 'hidden ' : ''}method="post" action="/auth/signin/microsoft-entra-id"><input type="hidden" name="csrfToken" value="${csrfToken}"><input type="hidden" name="callbackUrl" value="${client.origin}/"><input type="hidden" name="intent" value="${token}">${trusted ? '' : '<button>sign in with uoft</button>'}</form>
${trusted ? `<script nonce="${nonce}">document.forms[0].submit()</script>` : ''}</body></html>`, { headers: response.headers })
    page.headers.set('Content-Type', 'text/html; charset=utf-8')
    page.headers.set('Content-Security-Policy', `default-src 'none'; frame-ancestors 'none'; base-uri 'none'${trusted ? `; script-src 'nonce-${nonce}'` : ''}`)
    return page
  }
  if (url.pathname.startsWith('/auth/')) {
    let token: string | undefined
    let selectedIntent: JWT | undefined
    if (url.pathname === '/auth/signin/microsoft-entra-id' && request.method === 'POST') {
      token = (await request.clone().formData()).get('intent') as string
      if (!token) return new Response('login intent required', { status: 400 })
      selectedIntent = (await decode({ token, secret: env.AUTH_SECRET, salt: intentCookie(url) }))!
    }
    const result = await Auth(request, await config(request, env, url, selectedIntent))
    const response = new Response(result.body, result)
    const location = response.headers.get('Location')
    if (token && location && new URL(location, url).origin === 'https://login.microsoftonline.com') {
      response.headers.append('Set-Cookie', stringifySetCookie({ name: intentCookie(url), value: token,
        httpOnly: true, secure: url.protocol === 'https:', sameSite: 'lax', path: '/', maxAge: 900,
      }))
    }
    if (url.pathname.startsWith('/auth/callback/')) {
      response.headers.append('Set-Cookie', stringifySetCookie({ name: intentCookie(url), value: '', path: '/', maxAge: 0, secure: url.protocol === 'https:' }))
    }
    return response
  }
  if (url.pathname === '/') return Response.redirect(new URL('/me', url).href, 302)
  return new Response('not found', { status: 404 })
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const result = await route(request, env, new URL(request.url))
    const response = new Response(result.body, result)
    response.headers.set('Cache-Control', 'no-store')
    response.headers.set('Vary', 'Origin')
    const origin = request.headers.get('Origin')
    if (new URL(request.url).pathname === '/me' && origin) {
      response.headers.set('Access-Control-Allow-Origin', origin)
      response.headers.set('Access-Control-Allow-Credentials', 'true')
    }
    return response
  },
} satisfies ExportedHandler<Env>
