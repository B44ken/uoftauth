# uoftauth

cloudflare worker at https://uoftauth.boratto.ca. verifies access to a uoft microsoft member account, not current student enrolment.

send the browser to `/login?domain=muoft.ca`. the hosted page names the receiving origin; after sign-in, it returns to that site's homepage.

```js
const user = await fetch('https://uoftauth.boratto.ca/me', {
  credentials: 'include',
}).then(r => r.json())
```

`user` is `{ id, name, email }` or `null`. the encrypted, httponly session lasts one hour and renews when read. it authorizes only the origin chosen at login; another login replaces that choice. email and name can be null. auth responses aren't cached.

cookies use `SameSite=None; Secure`. browsers that block third-party cookies cannot use this fetch across unrelated domains. frontend visibility isn't backend authorization.

## setup

```sh
npm ci
cp .dev.vars.example .dev.vars
openssl rand -base64 48 # use as AUTH_SECRET
npm run dev
```

set `AUTH_MICROSOFT_ENTRA_ID_SECRET` in `.dev.vars`. the client id lives in `wrangler.jsonc`. register these microsoft **web** redirect uris:

- `https://uoftauth.boratto.ca/auth/callback/microsoft-entra-id`
- `http://localhost:8787/auth/callback/microsoft-entra-id`

the app requests `openid profile email User.Read`. microsoft graph distinguishes member accounts from guests. local frontend example: `/login?domain=http://localhost:5173`.

```sh
npm test
npm run typecheck
npx wrangler deploy --secrets-file .dev.vars
```

tests run the bundled worker with miniflare, including the oauth callback with mocked microsoft responses. live microsoft sign-in and the credentialed `/me` fetch from `https://muoft.ca` passed on 2026-10-17.

the production client secret is stored in cloudflare and expires on 2027-04-15.
