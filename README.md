# AuthzX Node SDK

TypeScript/JavaScript client for [AuthzX](https://authzx.com) — works with both AuthzX Cloud and the local AuthzX Agent.

Zero dependencies. Requires Node.js 18+ (uses native `fetch`).

## Install

```bash
npm install @authzx/sdk
```

## Usage

### Cloud Mode

```typescript
import { AuthzX } from '@authzx/sdk'

const authzx = new AuthzX({ apiKey: 'azx_...' })

const allowed = await authzx.check(
  { id: 'user:123', type: 'user', roles: ['editor'] },
  'read',
  { type: 'document', id: 'doc:456' }
)
```

### OAuth2 Client Credentials

For service-to-service auth, pass `clientId` + `clientSecret` (secret is prefixed `azx_cs_`). The SDK exchanges credentials at the token endpoint, caches the JWT in memory, and refreshes ~60s before expiry.

```typescript
const authzx = new AuthzX({
  clientId: 'my-client-id',
  clientSecret: 'azx_cs_...',
})
```

Equivalent curl for the underlying token exchange:

```bash
curl -X POST https://api.authzx.com/identity-srv/v1/oauth/token \
  -d grant_type=client_credentials \
  -d client_id=my-client-id \
  -d client_secret=azx_cs_...
```

Providing both `apiKey` and OAuth credentials is rejected at construction. A bad `clientId` / `clientSecret` surfaces as an `AuthzXOAuthError` (distinct from `AuthzXError`) with a message pointing you at the OAuth exchange.

### Agent Mode (local)

```typescript
const authzx = new AuthzX({ baseUrl: 'http://localhost:8181' })
```

### Full Evaluate Response

```typescript
const resp = await authzx.authorize({
  subject: { id: 'user:123', type: 'user' },
  action: 'read',
  resource: { type: 'document', id: 'doc:456' },
  context: { ip: '10.0.0.1' },
})
// resp.allowed, resp.reason, resp.policy_id, resp.access_path
```

### Express Middleware

```typescript
import express from 'express'

const app = express()
const authzx = new AuthzX({ apiKey: 'azx_...' })

// Protects route — extracts subject ID from X-User-ID header by default
app.get('/documents/:id', authzx.middleware('document', 'read'), (req, res) => {
  res.json({ ok: true })
})

// Custom subject ID extraction
app.get('/documents/:id', authzx.middleware('document', 'read', (req) => req.auth.userId), handler)
```

### Options

```typescript
new AuthzX({
  apiKey: 'azx_...',           // API key for cloud mode
  baseUrl: 'http://localhost:8181', // Custom URL (agent mode)
  timeout: 5000,                    // Request timeout in ms (default: 10000)
})
```

## Types

```typescript
interface Subject {
  id: string
  type: string
  attributes?: Record<string, unknown>
  roles?: string[]
}

interface Resource {
  type: string
  id: string
  attributes?: Record<string, unknown>
}

interface AuthorizeRequest {
  subject: Subject
  resource: Resource
  action: string
  context?: Record<string, unknown>
}

interface AuthorizeResponse {
  allowed: boolean
  reason: string
  policy_id?: string
  access_path?: string
}
```
