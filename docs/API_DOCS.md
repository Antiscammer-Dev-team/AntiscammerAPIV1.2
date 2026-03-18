# AntiScammer API Documentation

This document covers all endpoints except the Master API. For Master API (root/staff) endpoints, see [MASTER_API.md](MASTER_API.md).

**Base URL:** Your API base (e.g. `https://api.example.com`)

**Response headers:** All responses include `X-Request-ID` and `X-Response-Time-Ms`.

---

## Authentication

| Auth type      | Header / Method | Used by                         |
|----------------|-----------------|----------------------------------|
| API Key        | `X-API-Key`     | Partner APIs (lookup, detect, etc.) |
| Basic Auth     | `Authorization: Basic <base64>` | Admin dashboard              |
| None           | -               | /ready, /health                   |

---

## Public Endpoints (No Auth)

### Health check

```
GET /ready
```

**Response:**
```json
{
  "ok": true
}
```

---

### Health (detailed)

```
GET /health
```

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

---

## API Key Endpoints

All endpoints below require `X-API-Key: <your_api_key>`.

---

### User lookup (single)

```
GET /lookup/{user_id}?include_reason=true
```

| Param          | Type    | Description                    |
|----------------|---------|--------------------------------|
| user_id        | path    | Discord user ID                |
| include_reason | query   | If true, include ban reason    |

**Response:**
```json
{
  "user_id": "123456789",
  "is_flagged": true,
  "reason": "NSFW Discord Invite | Case #4015"
}
```

---

### User lookup (batch)

```
POST /lookup
Content-Type: application/json
```

**Request body:**
```json
{
  "user_ids": ["123456789", "987654321"],
  "include_reason": false
}
```

| Field         | Type    | Required | Description              |
|---------------|---------|----------|--------------------------|
| user_ids      | array   | yes      | 1–500 user IDs           |
| include_reason| boolean | no       | Include ban reasons      |

**Response:**
```json
{
  "count": 2,
  "results": [
    {
      "user_id": "123456789",
      "is_flagged": true,
      "reason": "NSFW Discord Invite"
    },
    {
      "user_id": "987654321",
      "is_flagged": false
    }
  ]
}
```

---

### Scam detection

```
POST /detect
Content-Type: application/json
```

**Request body:**
```json
{
  "message": "Check out this free nitro! discord.gg/abc123",
  "context_messages": [
    {
      "created_at": "2026-03-18T12:00:00Z",
      "author": "User1",
      "content": "Hey what's this link?"
    }
  ]
}
```

| Field           | Type   | Required | Description                  |
|-----------------|--------|----------|------------------------------|
| message         | string | yes      | Message to classify          |
| context_messages| array  | no       | Prior messages (for context) |

**Response:**
```json
{
  "is_scam": true,
  "decision": "scam",
  "uncertain": false,
  "confidence": "high",
  "reason": "Classic nitro scam with suspicious link.",
  "obfuscation": {
    "looks_vertical": false,
    "line_count": 1,
    "single_char_line_ratio": 0,
    "whitespace_ratio": 0.15
  }
}
```

| Field      | Type    | Description                           |
|------------|---------|---------------------------------------|
| is_scam    | boolean | True if decision is scam              |
| decision   | string  | `scam`, `not_scam`, or `uncertain`    |
| uncertain  | boolean | True if model was uncertain           |
| confidence | string  | `high`, `medium`, or `low`            |
| reason     | string  | Model's explanation                   |

---

### URL check (fast, no model)

```
POST /url-check
Content-Type: application/json
```

Look up URLs against the safe/scam database. No Ollama call.

**Request body:**
```json
{
  "urls": [
    "https://discord.gg/abc123",
    "https://goo.su/xyz"
  ]
}
```

| Field | Type  | Required | Description     |
|-------|-------|----------|-----------------|
| urls  | array | yes      | 1–100 URLs      |

**Response:**
```json
{
  "ok": true,
  "count": 2,
  "items": [
    {
      "url": "https://discord.gg/abc123",
      "domain": "discord.gg",
      "status": "unknown"
    },
    {
      "url": "https://goo.su/xyz",
      "domain": "goo.su",
      "status": "scam",
      "reason": "iplogger redirect"
    }
  ]
}
```

| status   | Description                        |
|----------|------------------------------------|
| safe     | Domain in whitelist                |
| scam     | Domain in scam database            |
| unknown  | Not in database                    |

---

### Canonicalize message

```
POST /canonicalize
Content-Type: application/json
```

Preprocess a message for scam analysis (used internally by /detect).

**Request body:**
```json
{
  "message": "Raw message text"
}
```

**Response:**
```json
{
  "raw": "...",
  "clean": "...",
  "joined": "...",
  "obfuscation": {
    "looks_vertical": false,
    "line_count": 1,
    "single_char_line_ratio": 0,
    "whitespace_ratio": 0.15
  }
}
```

---

## Ban Requests

### Submit ban request

```
POST /banrequest
Content-Type: multipart/form-data
```

| Field  | Type | Required | Description          |
|--------|------|----------|----------------------|
| user_id| text | yes      | Discord user ID      |
| reason | text | yes      | Ban reason           |
| notes  | text | no       | Additional notes     |
| proof  | file | yes      | Proof file (max 10MB)|

**Allowed file types:** .png, .jpg, .jpeg, .webp, .gif, .txt, .log, .json, .pdf, .zip

**Response:**
```json
{
  "ok": true,
  "case_id": "ABC123DEF456"
}
```

---

### Get ban request

```
GET /banrequest/{case_id}
```

**Response:** Full case record (case_id, user_id, reason, notes, status, proof_url, etc.)

---

### Resolve ban request

```
POST /banrequest/{case_id}/resolve
Content-Type: application/json
```

**Request body:**
```json
{
  "action": "approve",
  "decision_note": "Approved after review"
}
```

| Field         | Type   | Required | Description                    |
|---------------|--------|----------|--------------------------------|
| action        | string | yes      | `approve` or `reject`          |
| decision_note | string | no       | Reviewer note                  |

**Response:**
```json
{
  "ok": true,
  "case_id": "ABC123DEF456",
  "status": "approved"
}
```

---

## False Positive Reports

### Submit false positive report

```
POST /falsepositivereport
Content-Type: multipart/form-data
```

| Field  | Type | Required | Description          |
|--------|------|----------|----------------------|
| user_id| text | yes      | Discord user ID      |
| reason | text | yes      | Report reason        |
| notes  | text | no       | Additional notes     |
| proof  | file | yes      | Proof file (max 10MB)|

**Response:**
```json
{
  "ok": true,
  "case_id": "XYZ789ABC012"
}
```

---

### Get false positive report

```
GET /falsepositivereport/{case_id}
```

---

### Resolve false positive report

```
POST /falsepositivereport/{case_id}/resolve
Content-Type: application/json
```

**Request body:**
```json
{
  "action": "approve",
  "decision_note": "User was incorrectly flagged"
}
```

**Response:**
```json
{
  "ok": true,
  "case_id": "XYZ789ABC012",
  "status": "approved"
}
```

---

## 2FA Endpoints

### Setup 2FA

```
POST /2fa/setup
Content-Type: application/json
```

**Request body:**
```json
{
  "user_id": "123456789",
  "label": "optional_label"
}
```

**Response:**
```json
{
  "ok": true,
  "enabled": false,
  "user_id": "123456789",
  "issuer": "AntiScammer",
  "account": "label",
  "otpauth_url": "otpauth://totp/...",
  "secret_base32": "JBSWY3DPEHPK3PXP"
}
```

---

### Enable 2FA

```
POST /2fa/enable
Content-Type: application/json
```

**Request body:**
```json
{
  "user_id": "123456789",
  "code": "123456"
}
```

---

### Verify 2FA

```
POST /2fa/verify
Content-Type: application/json
```

**Request body:**
```json
{
  "user_id": "123456789",
  "code": "123456"
}
```

---

### Authenticate (alias for verify)

```
POST /authenticate
Content-Type: application/json
```

Same body and response as `/2fa/verify`.

---

### 2FA status

```
GET /2fa/status?user_id=123456789
```

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

## Admin Endpoints (Basic Auth)

All admin endpoints require HTTP Basic Authentication (username/password configured in the database). Access via `/admin` in a browser or with `Authorization: Basic <base64(username:password)>`.

**Rate limit:** 60 requests/minute per IP on admin API routes.

**Login throttling:** 5 failed attempts lock for 15 minutes.

---

### Admin Dashboard (HTML)

```
GET /admin
GET /admin/
```

Returns the admin dashboard HTML (tabbed UI for keys, URLs, scammers, users, ban requests, etc.).

---

### Dashboard stats

```
GET /admin/dashboard
```

**Response:**
```json
{
  "ok": true,
  "known_scammers_count": 150,
  "safe_urls_count": 5,
  "scam_urls_count": 2,
  "api_keys_count": 10,
  "admin_users_count": 2,
  "pending_ban_requests": 3,
  "pending_fp_reports": 1,
  "requests_total": 12345,
  "avg_response_ms": 150,
  "uptime_seconds": 86400,
  "pid": 1234
}
```

---

### API Keys (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/keys | List keys |
| GET | /admin/generate-key | Generate new key |
| POST | /admin/keys | Add key |
| PATCH | /admin/keys | Update key |
| DELETE | /admin/keys | Delete key (body: `{"key": "..."}`) |

---

### URL List (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/urls | List URLs |
| POST | /admin/urls | Add URL |
| DELETE | /admin/urls/{domain} | Delete URL |
| POST | /admin/reload-urls | Reload URL cache |

---

### Scammers (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/scammers | List scammers |
| POST | /admin/scammers | Add scammer |
| DELETE | /admin/scammers/{user_id} | Delete scammer |
| POST | /admin/reload-scammers | Reload scammer cache |

---

### Admin users

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/users | List admins |
| POST | /admin/users | Add admin |
| DELETE | /admin/users/{username} | Delete admin |
| PATCH | /admin/users/{username}/password | Change password |

---

### Ban requests (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/ban-requests?status=pending&limit=100 | List ban requests |
| POST | /admin/ban-requests/{case_id}/resolve | Resolve (approve/reject) |

---

### False positive reports (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/fp-reports?status=pending&limit=100 | List FP reports |
| POST | /admin/fp-reports/{case_id}/resolve | Resolve (approve/reject) |

---

### Master key (admin)

| Method | Path | Description |
|--------|------|-------------|
| GET | /admin/master-key | Get masked master key |
| POST | /admin/master-key | Set/clear master key |

---

## Error Responses

All errors return:
```json
{
  "detail": "Error message",
  "request_id": "abc123..."
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad request (validation) |
| 401 | Missing/invalid API key or admin credentials |
| 403 | Forbidden (e.g. login locked, wrong key type) |
| 404 | Resource not found |
| 413 | File too large |
| 429 | Rate limited |
| 500 | Internal server error |
