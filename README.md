# Vengtoo Node SDK

TypeScript/JavaScript client for [Vengtoo](https://vengtoo.com) — works with both Vengtoo Cloud and the Vengtoo Agent.

Zero dependencies. Requires Node.js 18+ (uses native `fetch`).

## Install

```bash
npm install @vengtoo/sdk
```

## Usage

### Cloud Mode

```typescript
import { Vengtoo } from '@vengtoo/sdk'

const vengtoo = new Vengtoo({ apiKey: 'azx_...' })

const allowed = await vengtoo.check(
  { id: 'user:123', type: 'user', roles: ['editor'] },
  'read',
  { type: 'document', id: 'doc:456' }
)
```

### OAuth2 Client Credentials

For service-to-service auth, pass `clientId` + `clientSecret` (secret is prefixed `azx_cs_`). The SDK exchanges credentials at the token endpoint, caches the JWT in memory, and refreshes ~60s before expiry.

```typescript
const vengtoo = new Vengtoo({
  clientId: 'my-client-id',
  clientSecret: 'azx_cs_...',
})
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.vengtoo.com/identity-srv/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both `apiKey` and OAuth credentials is rejected at construction. A bad `clientId` / `clientSecret` surfaces as an `VengtooOAuthError` (distinct from `VengtooError`) with a message pointing you at the OAuth exchange.

### Agent Mode (local)

```typescript
const vengtoo = new Vengtoo({ baseUrl: 'http://localhost:8181' })
```

### Full Evaluate Response

```typescript
const resp = await vengtoo.authorize({
  subject: { id: 'user:123', type: 'user' },
  action: { name: 'read' },
  resource: { type: 'document', id: 'doc:456' },
  context: { ip: '10.0.0.1' },
})
// resp.decision, resp.context?.reason, resp.context?.policy_id, resp.context?.access_path
```

### Express Middleware

```typescript
import express from 'express'

const app = express()
const vengtoo = new Vengtoo({ apiKey: 'azx_...' })

// Protects route — extracts subject ID from X-User-ID header by default
app.get('/documents/:id', vengtoo.middleware('document', 'read'), (req, res) => {
  res.json({ ok: true })
})

// Custom subject ID extraction
app.get('/documents/:id', vengtoo.middleware('document', 'read', (req) => req.auth.userId), handler)
```

### Options

```typescript
new Vengtoo({
  apiKey: 'azx_...',           // API key for cloud mode
  baseUrl: 'http://localhost:8181', // Custom URL (agent mode)
  timeout: 5000,                    // Request timeout in ms (default: 10000)
})
```

## Types

```typescript
interface Subject {
  id: string
  type?: string
  attributes?: Record<string, unknown>
  properties?: Record<string, unknown>
  roles?: string[]
}

interface Resource {
  id: string
  type?: string
  attributes?: Record<string, unknown>
  properties?: Record<string, unknown>
}

interface Action {
  name: string
  properties?: Record<string, unknown>
}

interface AuthorizeRequest {
  subject: Subject
  resource: Resource
  action: Action
  context?: Record<string, unknown>
}

interface AuthorizeContext {
  reason?: string
  reason_code?: string
  policy_id?: string
  access_path?: string
}

interface AuthorizeResponse {
  decision: boolean
  context?: AuthorizeContext
}
```
