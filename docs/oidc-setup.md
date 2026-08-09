---
title: Single sign-on setup
description: Configure OIDC single sign-on, map identity provider roles to Praxis roles, and troubleshoot the flow.
---

Praxis authenticates single sign-on users with the **OIDC Authorization Code
flow** against a **confidential client**. Any provider that publishes a standard
discovery document (`/.well-known/openid-configuration`) works; this guide uses
**Keycloak** as the worked example and then gives a generic checklist for other
providers (Okta, Azure AD, Auth0, Google Workspace, …).

Operators register providers in the UI at **Settings → Admin → OIDC Providers**.
This document covers the deployment-side prerequisites (URLs, environment
variables, and the claims your IdP must emit) that the UI form can't set for you.

## How it works

1. A user clicks the provider's **Sign in** button, which sends the browser to
   Praxis at `/api/backend/auth/oidc/login`.
2. Praxis generates a `state` and `nonce`, stores them, and redirects the
   browser to your IdP's authorization endpoint (`response_type=code`, your
   client ID, the exact redirect URI, scope `openid email profile`).
3. After the user authenticates, the IdP redirects back to Praxis at
   `/api/backend/auth/oidc/callback` with an authorization `code`.
4. Praxis exchanges the code for tokens, validates the **ID token**, maps its
   role claim to a Praxis role, provisions/updates the user, and redirects the
   browser to `/login` with short-lived Praxis tokens in the URL fragment (which
   the frontend swaps for httpOnly cookies). On failure it redirects to
   `/login?oidc_error=<code>` with a non-sensitive error code.

## Praxis URLs and environment variables

Praxis sits behind a frontend proxy: the browser-facing path
`/api/backend/auth/oidc/callback` is proxied to the backend. The IdP always
talks to the **public** URL, so the redirect URI you register must be the
public one.

| Variable | Purpose | Default |
| --- | --- | --- |
| `PUBLIC_BASE_URL` | The browser-facing Praxis origin. Used to build the redirect URI and the post-login return URL. | `https://localhost` |
| `OIDC_REDIRECT_URI` | Optional. Pin the **exact** redirect URI to register with the IdP. When unset, Praxis derives it from `PUBLIC_BASE_URL`. | *(derived)* |

- **Set `PUBLIC_BASE_URL` to your real external origin in production**, e.g.
  `https://praxis.example.com`. If it still points at `localhost`, the redirect
  URI and the post-login return URL will be wrong and SSO will fail.
- When `OIDC_REDIRECT_URI` is unset, the redirect URI is:
  `PUBLIC_BASE_URL` + `/api/backend/auth/oidc/callback`.
- **The redirect URI to register with your IdP for a normal production
  deployment is therefore:**

  ```
  https://<praxis-host>/api/backend/auth/oidc/callback
  ```

- Set `OIDC_REDIRECT_URI` explicitly when your external URL differs from what
  Praxis would derive (extra path prefix, a load balancer rewriting the host,
  etc.). Praxis re-uses the **exact** redirect URI it sent at authorize time
  when it exchanges the code, so the registered value, `OIDC_REDIRECT_URI` (if
  set), and the derived value must all agree.

> The Praxis **backend** must be able to reach the IdP's discovery and JWKS URLs
> directly (server-to-server), separate from the browser reaching the IdP. In
> segmented networks, allow backend egress to your IdP.

## Keycloak walkthrough

1. **Realm** — create or select the realm your users live in.
2. **Client** — create a client:
   - **Client type:** OpenID Connect.
   - **Client authentication:** ON (this makes it a *confidential* client with a
     secret — required).
   - **Standard flow:** ENABLED (this is the Authorization Code flow). Direct
     access grants / implicit are not needed.
3. **Valid redirect URIs** — add your exact Praxis redirect URI:
   `https://<praxis-host>/api/backend/auth/oidc/callback`.
4. **Web origins** — add your Praxis origin (`https://<praxis-host>`) so the
   browser exchange is allowed.
5. **Credentials** — copy the client secret and paste it into the Praxis
   provider form along with the client ID and the realm's issuer URL
   (`https://<keycloak-host>/realms/<realm>`).
6. **Identity claims** — make sure `email`, `preferred_username`, and profile
   claims are present in the token (the default `email` and `profile` client
   scopes cover this).
7. **Emit roles into the ID token** — this is the step people miss. Add a
   mapper that puts the user's roles into the **ID token**:
   - **Realm roles:** add a *User Realm Role* mapper. Roles land at
     `realm_access.roles`.
   - **Client roles:** add a *User Client Role* mapper for this client. Roles
     land at `resource_access.<client-id>.roles`.
   - On the mapper, **enable "Add to ID token."** Keycloak's role mappers put
     roles in the access token by default; Praxis validates the **ID token**, so
     the roles must be added there too.
8. **Role claim path in Praxis** — set the provider's **role claim** to the
   dotted path you chose above (`realm_access.roles` or
   `resource_access.<client-id>.roles`), and map the emitted values to Praxis
   roles (see [Role mapping](#role-mapping)).

## Generic OIDC provider checklist

For any non-Keycloak provider, confirm:

- **Discovery URL** — the provider publishes `/.well-known/openid-configuration`.
  Praxis reads the `issuer`, authorization endpoint, token endpoint, and
  `jwks_uri` from it.
- **Confidential client** using the **Authorization Code flow**
  (`response_type=code`) with a client secret.
- **Redirect URI** registered with an **exact** string match to
  `https://<praxis-host>/api/backend/auth/oidc/callback` (or your
  `OIDC_REDIRECT_URI`).
- **Scopes** — `openid email profile` at minimum. Add whatever provider-specific
  scope is required to include roles/groups in the token.
- **Issuer and JWKS reachable** from the Praxis backend.
- **Role claim in the ID token** — the claim you point Praxis at must be present
  in the **ID token**, not only in the access token or the userinfo response.
- **Identity claims** — `sub` (stable subject), plus `email` /
  `preferred_username` for a usable account.
- **Clock sync** — the IdP and Praxis hosts should agree on time (NTP); token
  `exp`/`iat`/`nbf` and `nonce` checks are time-sensitive.

## Role mapping

Praxis reads the configured **role claim** from the **ID token** and turns its
values into Praxis roles. The claim path is **dotted**, so a nested claim is
addressed by its full path:

- `realm_access.roles` — Keycloak realm roles.
- `resource_access.<client-id>.roles` — Keycloak client roles.
- A top-level claim like `roles` also works (a single unqualified segment). If
  no role claim is configured, Praxis looks for a top-level `roles` claim.

Each value found at that path is resolved to a Praxis role **only through the
provider's explicit role mapping allowlist**:

1. Configure a **role mapping** — a JSON map of IdP value → Praxis role, e.g.
   `{"praxis-admins": "admin", "praxis-ops": "maintainer"}`. Only claim values
   present as keys in this map, resolving to a real Praxis role, grant that role.
2. There is **no direct pass-through**. An IdP claim value of `admin`,
   `maintainer`, or `auditor` grants nothing on its own — the value must be
   allowlisted in the mapping (map `"admin": "admin"` explicitly if your IdP
   really does emit Praxis role names and you trust them). This prevents a hostile
   or misconfigured IdP from handing itself Praxis admin via a `roles: ["admin"]`
   claim.

Roles that can be mapped: **`admin`**, **`maintainer`**, **`auditor`**, and
**`viewer`**. A user can receive more than one; the effective permission is the
union.

> **Default when no role maps:** if the role claim is missing, or none of its
> values map to a Praxis role, the user is provisioned as **`auditor`**
> (read-only). Configure your mapping so privileged users don't silently land
> read-only — and so unknown users get the least privilege by default.

## Account provisioning and linking

Praxis binds an SSO login to the stable **`(issuer, sub)`** identity from the ID
token — never to a matching username or email. This is deliberate and fails
closed to prevent account takeover:

- **Returning users** are matched only by `(issuer, sub)`. If that user is
  disabled in Praxis, login is refused (no tokens are issued).
- **New users** are created only when the IdP asserts a **verified email**
  (`email_verified: true` in the ID token). A login without a verified email
  cannot create an account.
- **No auto-linking.** If a new OIDC subject's username or email collides with an
  **existing** Praxis account (e.g. a local admin), the login **fails** — Praxis
  never rewrites the existing account into an OIDC-linked one. To let an existing
  operator sign in via SSO, an admin must reconcile that account deliberately;
  a matching email claim alone is not accepted as proof of ownership.

Callback failures surface a generic `sso_failed` (or `invalid_state`) to the
browser; the specific reason is logged server-side.

## Security and validation behavior

- **State and nonce** are generated per login attempt, stored server-side with a
  **10-minute TTL**, and are **single-use**: the callback consumes the `state`
  row atomically, so a replayed or concurrent callback with the same `state`
  fails. An expired state is rejected.
- **ID token validation** checks, in one step:
  - the **issuer** matches the discovery document's `issuer`,
  - the **audience** matches your client ID,
  - the signature verifies against the matching **JWKS** key (`kid`, RS256),
  - the **`nonce`** matches the one issued at login.
- **`at_hash`** — providers that include an `at_hash` claim in the ID token
  (Keycloak does) are validated correctly, because Praxis passes the access
  token into ID-token validation so the `at_hash` binding can be checked.

## Troubleshooting

- **`invalid_redirect_uri` / the IdP rejects the redirect** — the redirect URI
  registered at the IdP doesn't exactly match what Praxis sent. Confirm
  `PUBLIC_BASE_URL` (or `OIDC_REDIRECT_URI`) resolves to
  `https://<praxis-host>/api/backend/auth/oidc/callback` and that the IdP has
  that exact string, scheme and all.
- **SSO logs in but the user is only `auditor` / has no privileges** — the role
  claim almost certainly isn't in the **ID token**. Roles that appear only in
  the **access token** or the **userinfo** response are not seen by Praxis. In
  Keycloak, enable "Add to ID token" on the role mapper; on other providers, add
  the role/group claim to the ID token. Also confirm the Praxis role claim path
  matches where the roles actually land (`realm_access.roles` vs
  `resource_access.<client-id>.roles`).
- **`Invalid issuer` / signature or key errors** — the issuer in the token
  doesn't match the discovery document, or the backend can't fetch the current
  JWKS. Verify the issuer URL and that the backend can reach the JWKS endpoint.
- **Token expired / `nonce`/`iat` errors that come and go** — clock skew.
  Ensure the IdP and Praxis hosts are NTP-synced.
- **Login fails only after an upgrade, with an `at_hash` error** — very old
  builds validated the ID token without the access token and could reject
  Keycloak tokens carrying `at_hash`. Current builds pass the access token into
  validation; make sure you're on a current build.
- **Backend can't reach discovery/JWKS** — the browser reaching the IdP is not
  enough; the Praxis **backend** must reach the IdP's discovery and JWKS URLs.
  Open backend egress to the IdP.
- **Everything 404s / redirect returns to the wrong place** — `PUBLIC_BASE_URL`
  doesn't match the origin the browser actually uses, or the proxy in front of
  Praxis isn't forwarding `/api/backend/...` to the backend. Fix the public
  origin and proxy routing.

## See also

- [Production Hardening](production-hardening.md) — deployment shapes and
  environment validation.
- In-app help: **Settings → Admin** documents the OIDC provider form and the
  role-claim mapping note.
