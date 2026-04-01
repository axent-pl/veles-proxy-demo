# Veles Proxy Demo

This repository is a minimal demonstration of `Veles Proxy` as a security gateway.

It shows that `Veles Proxy` can:

- authenticate a user or client with one protocol
- enrich identity data between authentication and credential issuance
- reissue the resulting identity in a completely different form

In this demo, the flow is:

1. The user authenticates with OAuth2 / OpenID Connect against the demo authorization server.
2. `Veles Proxy` stores session state and reads the OIDC subject identifier.
3. `Veles Proxy` enriches that identity with an LDAP lookup against Samba AD.
4. `Veles Proxy` issues Kerberos SPNEGO credentials toward the upstream application.

The result is a protocol bridge from OIDC to Kerberos, with an identity-mapping step in the middle.

## What Runs Here

The stack started by this repository contains:

- `auth-proxy` - `axproxy`, listening on `https://localhost:7700` and `https://localhost:7711`
- `auth-server` - a demo OIDC provider on `http://localhost:7777`
- `samba-ad` - Samba Active Directory used for LDAP and Kerberos
- `app-upstream` - a sample Kerberos-protected upstream application
- `session-db` - Redis session storage for `Veles Proxy`

This demo is intentionally small and focused. The `Veles Proxy` part is a single container image with a compact runtime role in the flow: authenticate, enrich, translate credentials, and forward traffic. The surrounding services exist only to make the end-to-end scenario reproducible.

## Run It

Start the environment with either of these commands:

```bash
make up
```

or

```bash
docker-compose up -d --build
```

Stop it with:

```bash
make down
```

or

```bash
docker-compose down
```

## Demo Endpoints

After startup:

- OIDC server: `http://localhost:7777`
- Main `axproxy` listener: `https://localhost:7700`
- Second `axproxy` listener: `https://localhost:7711`

The primary demo path is `https://localhost:7700`.

When the user hits that endpoint, `axproxy` redirects to the OIDC server, authenticates the user, performs enrichment, then obtains and forwards Kerberos credentials to the upstream app.

Demo OIDC users from [`volumes/vol-axes-config/config.json`](./volumes/vol-axes-config/config.json):

- `demo` / `demo`
- `admin` / `admin`

## Authentication And Translation Flow

The core `axproxy` chain is defined in [`volumes/vol-axproxy-config/config.yaml`](./volumes/vol-axproxy-config/config.yaml):

```yaml
chain:
  - Audit
  - Session
  - AuthOIDC
  - Enrichment
  - Enrichment
  - Rewriter
  - CustomHeaders
  - IssueSPNEGO
```

That chain demonstrates the intended gateway behavior:

- `AuthOIDC` authenticates users with OpenID Connect
- `Enrichment` adds or maps identity attributes before credentials are issued
- `IssueSPNEGO` reissues the authenticated identity as Kerberos SPNEGO toward the upstream service

In this repository, the LDAP mapping step converts the OIDC subject into an AD account attribute:

```yaml
kind: Enrichment
metadata:
  name: ldap
spec:
  sources:
    - name: ldap
      type: ldap
      ldap:
        addr: "ldap://samba-ad:389"
  lookups:
    - name: sAMAccountName
      source: ldap
      inputs:
        "employeeNumber": ${session.oidc_subject_id}
      mappings:
        "session.sAMAccountName": ${sAMAccountName}
```

The final SPNEGO issuance uses that mapped account:

```yaml
kind: IssueSPNEGO
metadata:
  name: spnego
spec:
  inputs:
    user_principal: ${session.sAMAccountName}
  issuer:
    delegate: true
    credentials_principal: proxy_svc
    target_principal: HTTP/app_svc.example.local@EXAMPLE.LOCAL
```

So the effective demo story is:

- authenticate with OIDC
- map identity with LDAP
- access a Kerberos-protected upstream using SPNEGO issued by `axproxy`

## Why This Demo Is Minimal

This repository is meant to highlight the gateway behavior, not bury it under a large platform setup.

- `axproxy` configuration lives in a single file: [`config.yaml`](./volumes/vol-axproxy-config/config.yaml)
- the upstream demo app is intentionally small and only exists to prove Kerberos/SPNEGO handoff
- the compose stack is limited to the services required to demonstrate OIDC, LDAP, Kerberos, and session storage

That makes it a good starting point for evaluating `axproxy` as a lightweight component with a small operational footprint in terms of image size, CPU usage, and memory use, while still supporting protocol translation and enrichment.

## Why It Is Configurable

The demo also shows that `Veles Proxy` behavior is driven by configuration rather than custom code.

### Multiple listeners and upstreams

Two `AuthProxy` definitions are configured:

```yaml
kind: AuthProxy
metadata:
  name: default
spec:
  listen: ":7700"
  upstreams:
    - source: https://localhost:7700
      target: http://app-upstream:8080
---
kind: AuthProxy
metadata:
  name: second
spec:
  listen: ":7711"
  upstreams:
    - source: https://localhost:7711
      target: https://docs.python.org
```

This shows that the same image can expose different entrypoints and protect different upstream targets.

### Different session backends

The config includes both in-memory style session settings and Redis-backed sessions:

```yaml
kind: Session
metadata:
  name: redis
spec:
  driver: redis
  redis:
    addr: session-db:6379
```

### Encryption for persistent session backends

Session data stored in persistent backend (Redis) can be ecrypted to increase security:

```yaml
apiVersion: v1
kind: Session
metadata:
  name: redis
spec:
  encryptor:
    path: assets/keys/session.key
    kid: default
```

### Header and content rewriting

The demo modifies headers and rewrites URLs:

```yaml
kind: CustomHeaders
metadata:
  name: cors
spec:
  request:
    - op: del
      header: X-Forwarded-For
```

```yaml
kind: Rewriter
metadata:
  name: url
spec:
  rewrite:
    "https://pl.wikipedia.org": "https://localhost:8787"
    "https://docs.python.org": "https://localhost:8989"
  headers: true
  body: true
```

### OIDC client settings from environment

The OIDC module is parameterized with environment variables:

```yaml
kind: AuthOIDC
metadata:
  name: axes
spec:
  client_id: ${AXES_CLIENT}
  client_secret: ${AXES_SECRET}
```

That makes the same config pattern easy to adapt across environments.

## Demo Data Provisioned In AD

The Samba provisioning script creates the principals and mappings needed for the demo:

- AD user `testuser`
- service accounts `app_svc` and `proxy_svc`
- Kerberos keytabs for the app and proxy
- delegation from `proxy_svc` to the upstream HTTP service

See [`services/samba-ad/scripts/provision.sh`](./services/samba-ad/scripts/provision.sh).

## Files To Inspect

If you want to understand or adapt the demo, start with:

- [`README.md`](./README.md)
- [`docker-compose.yaml`](./docker-compose.yaml)
- [`makefile`](./makefile)
- [`volumes/vol-axproxy-config/config.yaml`](./volumes/vol-axproxy-config/config.yaml)
- [`volumes/vol-axes-config/config.json`](./volumes/vol-axes-config/config.json)
