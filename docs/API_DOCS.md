# AntiScammer API Documentation (Partner & Public)

This document describes **public** endpoints and **API key** (`X-API-Key`) endpoints.

It does **not** include:

- **`/admin/*`** — browser dashboard and admin JSON APIs (HTTP Basic Auth).
- **Master API** — routes that require the master API key, e.g. **`/root/*`** and **`POST /staff/signal/antiscam/global-ban`**. See [MASTER_API.md](MASTER_API.md).

**Base URL:** Your API base (e.g. `https://api.example.com`)

**Response headers:** Successful and error responses typically include `X-Request-ID` and `X-Response-Time-Ms`.

---

## Authentication

| Auth type | Header / method | Used by |
|-----------|-----------------|--------|
| None | — | `/ready`, `/health` |
| API key | `X-API-Key: <key>` | All other documented routes below except public health |

API keys are validated against expiry and stored metadata (see key management in admin docs).

---

## Public endpoints (no API key)

### `GET /ready`

Lightweight liveness probe.

**Response:**

```json
{ "ok": true }
```

---

### `GET /health`

Readiness-style check: DB-backed stats for load balancers or monitoring.

**Response:**

```json
{
  "ok": true,
  "db_loaded": true,
  "known_scammers_count": 150,
  "twofa_keys_count": 2,
  "twofa_users_count": 10,
  "twofa_enabled_users_count": 5,
  "utc": "2026-03-18T12:00:00Z"
}
```

| Field | Description |
|-------|-------------|
| known_scammers_count | Rows in the in-memory banlist cache |
| twofa_* | 2FA records aggregated across API keys |
| utc | Current server time (UTC, ISO-8601 Z) |

---

### `GET /`

Returns **404** with JSON `{"detail":"Not found"}`. Use a specific path from this document for API calls.

---

## API key endpoints

All routes in this section require:

```http
X-API-Key: <your_api_key>
```

---

## User lookup

### `GET /lookup/{user_id}`

| Param | Type | Description |
|-------|------|-------------|
| user_id | path | Discord user ID (digits; non-digits are stripped server-side) |
| include_reason | query | If `true`, include `reason` when user is flagged |

**Response:**

```json
{
  "user_id": "123456789",
  "is_flagged": true,
  "reason": "NSFW Discord Invite | Case #4015"
}
```

`reason` is omitted when `is_flagged` is false or when `include_reason` is false.

**Errors:** `400` if no numeric user id remains after normalization.

---

### `POST /lookup`

Batch lookup (same logic as single lookup).

**Content-Type:** `application/json`

**Body:**

```json
{
  "user_ids": ["123456789", "987654321", "bad"],
  "include_reason": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_ids | array | yes | 1–500 entries |
| include_reason | boolean | no | Include ban reasons when flagged |

**Response:**

```json
{
  "count": 3,
  "results": [
    { "user_id": "123456789", "is_flagged": true, "reason": "..." },
    { "user_id": "987654321", "is_flagged": false },
    { "user_id": "bad", "is_flagged": false, "error": "invalid_user_id" }
  ]
}
```

Invalid entries receive `is_flagged: false` and an `error` field instead of a normalized id.

---

## Scam detection

### `POST /detect`

Runs the configured Ollama model (see server env: `OLLAMA_*`) on the message. Falls back to heuristics when the model errors or returns invalid JSON.

**Content-Type:** `application/json`

**Body:**

```json
{
  "message": "Text to classify",
  "context_messages": [
    {
      "created_at": "2026-03-18T12:00:00Z",
      "author": "User1",
      "content": "Prior line"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| message | string | yes | Main message |
| context_messages | array | no | Optional prior messages |

**Response (typical):**

```json
{
  "is_scam": true,
  "decision": "scam",
  "uncertain": false,
  "confidence": "high",
  "reason": "Explanation from the model or heuristics.",
  "obfuscation": {
    "looks_vertical": false,
    "line_count": 1,
    "single_char_line_ratio": 0,
    "whitespace_ratio": 0.15
  }
}
```

| Field | Description |
|-------|-------------|
| decision | `scam`, `not_scam`, or `uncertain` |
| confidence | `high`, `medium`, `low`, or `null` on some error paths |
| uncertain | `true` when decision is `uncertain` |

---

## URL check

### `POST /url-check`

Fast domain classification against the safe/scam URL database (no LLM).

**Content-Type:** `application/json`

**Body:**

```json
{ "urls": ["https://example.com/path", "goo.su/x"] }
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| urls | array | yes | 1–100 URL strings |

**Response:**

```json
{
  "ok": true,
  "count": 2,
  "items": [
    { "url": "https://example.com/path", "domain": "example.com", "status": "safe" },
    { "url": "goo.su/x", "domain": "goo.su", "status": "scam", "reason": "..." }
  ]
}
```

| status | Meaning |
|--------|---------|
| safe | Domain on the allow list |
| scam | Domain on the block list (`reason` may be present) |
| unknown | Not listed (first domain extracted from each string) |

---

## Canonicalize

### `POST /canonicalize`

Preprocesses a message the same way as `/detect` (obfuscation stats, cleaned/joined text). Useful for debugging integrations.

**Content-Type:** `application/json`

**Body:**

```json
{ "message": "Raw message text" }
```

**Response:** Includes `raw`, `clean`, `joined`, and `obfuscation` (same shape as in `/detect`).

---

## Ticket audit (giveaway verification)

Used to register expected Discord winner IDs for a giveaway, then verify who opens a ticket. Claims are stored **per giveaway session** (`audit_id`). The same Discord user can win **different** giveaways (different `audit_id` from separate registers). Optional `giveaway_key` is your own label for auditing.

**Environment (server):**

| Variable | Default | Description |
|----------|---------|-------------|
| `TICKET_AUDIT_TTL_DAYS` | `14` | Session expiry (clamped 1–365) |
| `TICKET_AUDIT_DELAY_SEC` | `1.0` | Delay before building the lookup response |
| `TICKET_AUDIT_CLAIM_RETENTION_DAYS` | `30` | How long a resolved claim blocks re-use (clamped 1–365) |

---

### `POST /ticket-audit/register`

**Content-Type:** `application/json`

**Body:**

```json
{
  "discord_ids": ["123456789012345678", "987654321098765432"],
  "store": "Optional store name",
  "server_id": "optional_discord_guild_snowflake",
  "giveaway_key": "optional_stable_id_for_your_logs"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| discord_ids | array | yes | 1–100 strings; blank/invalid entries are skipped |
| store | string | no | Free-form label |
| server_id | string | no | Discord guild ID; if set, verify must send the same `server_id` |
| giveaway_key | string | no | Your giveaway identifier (echoed on verify); uniqueness is still by `audit_id` |

**Response:**

```json
{
  "audit_id": "hex_string",
  "expires_at": "2026-04-04T12:00:00Z",
  "server_id": "111",
  "giveaway_key": "spring-drop-2026"
}
```

`server_id` and `giveaway_key` appear only when provided.

**Errors:**

- `400` — `No valid discord_ids: all entries were blank or invalid`

---

### `POST /ticket-audit/verify`

**Content-Type:** `application/json`

**Body:**

```json
{
  "audit_id": "from_register",
  "discord_id": "123456789012345678",
  "include_reason": true,
  "server_id": "optional_guild_if_session_had_server_id"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| audit_id | string | yes | Session id from register |
| discord_id | string | yes | Cannot be blank; must normalize to digits |
| include_reason | boolean | no | Passed through to banlist lookup |
| server_id | string | conditionally | **Required** and must match if the session was created with `server_id` |

After a short delay (`TICKET_AUDIT_DELAY_SEC`), the response includes banlist lookup for that Discord user (same fields as `GET /lookup`).

**First successful claim (winner matches list, not yet claimed):**

```json
{
  "audit_id": "...",
  "id_match": true,
  "user_id": "123456789012345678",
  "lookup": { "user_id": "123456789012345678", "is_flagged": false },
  "giveaway_key": "spring-drop-2026",
  "claimed": true,
  "resolved_at": "2026-03-18T12:00:01Z",
  "retain_until": "2026-04-17T12:00:01Z"
}
```

**Mismatch (id not in registered list):**

```json
{
  "audit_id": "...",
  "id_match": false,
  "message": "Ids do not match. Checking user.",
  "user_id": "...",
  "lookup": { "user_id": "...", "is_flagged": false }
}
```

**Already claimed (same user + same `audit_id` within retention):**

```json
{
  "audit_id": "...",
  "id_match": true,
  "already_claimed": true,
  "message": "This ID has already been claimed",
  "user_id": "...",
  "lookup": { "...": "..." },
  "resolved_at": "...",
  "retain_until": "...",
  "giveaway_key": "..."
}
```

**Errors:**

- `400` — `discord_id cannot be blank`, `discord_id must contain a valid numeric Discord user ID`, or `server_id is required and must match this audit session`
- `404` — `Audit session not found or expired` (wrong key, unknown id, or past session expiry)

---

## Ban requests

### `POST /banrequest`

**Content-Type:** `multipart/form-data`

| Field | Required | Description |
|-------|----------|-------------|
| user_id | yes | Discord user id |
| reason | yes | Ban reason |
| notes | no | Extra notes |
| proof | yes | File, max 10 MB |

Allowed proof extensions: `.png`, `.jpg`, `.jpeg`, `.webp`, `.gif`, `.txt`, `.log`, `.json`, `.pdf`, `.zip`

**Response:**

```json
{ "ok": true, "case_id": "ABC123DEF456" }
```

---

### `GET /banrequest/{case_id}`

Returns the case record (JSON), including `status`, `user_id`, `reason`, `proof_url`, etc.

**Errors:** `404` if unknown case id.

---

### `POST /banrequest/{case_id}/resolve`

**Content-Type:** `application/json`

**Body:**

```json
{
  "action": "approve",
  "decision_note": "Optional reviewer note"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| action | yes | `approve` or `reject` |
| decision_note | no | Stored in review metadata |

On **approve**, the subject user is added to the global banlist (and mirrored to MariaDB when configured).

**Response:**

```json
{ "ok": true, "case_id": "ABC123DEF456", "status": "approved" }
```

`status` is `approved` or `rejected`.

---

## False positive reports

### `POST /falsepositivereport`

Same shape as `POST /banrequest` (`user_id`, `reason`, `notes`, `proof` file).

**Response:**

```json
{ "ok": true, "case_id": "XYZ789ABC012" }
```

---

### `GET /falsepositivereport/{case_id}`

Returns the FP report JSON.

---

### `POST /falsepositivereport/{case_id}/resolve`

Same body as ban request resolve (`action`, `decision_note`).

**Response:**

```json
{ "ok": true, "case_id": "XYZ789ABC012", "status": "approved" }
```

---

## Two-factor authentication (2FA)

2FA secrets are scoped to **`(X-API-Key, user_id)`**. All 2FA routes require a valid API key header.

---

### `POST /2fa/setup`

**Content-Type:** `application/json`

**Body:**

```json
{ "user_id": "123456789", "label": "optional_account_label" }
```

**Response (setup or already enabled):**

```json
{
  "ok": true,
  "enabled": false,
  "user_id": "123456789",
  "issuer": "AntiScammer",
  "account": "PartnerLabel:123456789",
  "otpauth_url": "otpauth://totp/...",
  "secret_base32": "..."
}
```

If 2FA is already enabled for that pair, `enabled` may be `true` and `detail` explains it.

---

### `POST /2fa/enable`

**Body:**

```json
{ "user_id": "123456789", "code": "123456" }
```

**Response:**

```json
{ "ok": true, "enabled": true, "user_id": "123456789" }
```

**Errors:** `400` if setup was not done; `401` if code invalid.

---

### `POST /2fa/verify`

**Body:**

```json
{ "user_id": "123456789", "code": "123456" }
```

**Response:**

```json
{ "ok": true, "valid": true, "user_id": "123456789" }
```

**Errors:** `403` if 2FA not enabled for that key/user; `401` invalid code.

---

### `POST /authenticate`

Same request/response behavior as `POST /2fa/verify`.

---

### `GET /2fa/status`

| Param | Type | Required |
|-------|------|----------|
| user_id | query | yes |

**Response:**

```json
{
  "ok": true,
  "user_id": "123456789",
  "enabled": true,
  "has_secret": true,
  "label": "Partner:123456789"
}
```

---

## Error responses

JSON error bodies typically look like:

```json
{
  "detail": "Human-readable message",
  "request_id": "hex..."
}
```

| Status | Typical cause |
|--------|----------------|
| 400 | Validation, missing form fields, invalid action |
| 401 | Missing/invalid API key, invalid 2FA code |
| 403 | 2FA not enabled, or other forbidden states |
| 404 | Unknown `case_id`, unknown ticket audit session |
| 413 | Upload too large (e.g. ban report proof > 10 MB) |
| 429 | Too many requests (e.g. admin routes; partner routes may add limits separately) |
| 500 | Unexpected server failure |

---

## Related documentation

- [MASTER_API.md](MASTER_API.md) — `/root/*` and other master-key routes (not covered here).
