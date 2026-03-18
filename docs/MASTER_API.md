# AntiScammer Master API Documentation

All endpoints in this document require the **Master API Key**. The master key must be configured in the admin dashboard and passed via the `X-API-Key` header. These endpoints are intended for automation, integrations, and fully privileged management.

**Authentication:** `X-API-Key: <master_key>`

**Base URL:** Your API base (e.g. `https://api.example.com`)

**Response envelope:** All success responses include `"ok": true`. Errors return `{"detail": "...", "request_id": "..."}`.

---

## API Keys

### List API keys

```
GET /root/api-keys
```

**Response:**
```json
{
  "keys": [
    {
      "key": "ATSM-XXXX-XXXX-XXXX",
      "key_masked": "ATSM-****-****-XXXX",
      "label": "Modora",
      "expires_at": "2027-12-31T23:59:59Z",
      "bypass_ratelimit": false
    }
  ]
}
```

---

### Create API key

```
POST /root/api-keys
Content-Type: application/json
```

**Request body:**
```json
{
  "key": "ATSM-XXXX-XXXX-XXXX",
  "label": "Partner name",
  "expires_at": "2027-12-31T23:59:59Z",
  "bypass_ratelimit": false
}
```

| Field           | Type    | Required | Description                                        |
|-----------------|---------|----------|----------------------------------------------------|
| key             | string  | yes      | API key value (min 4 chars)                        |
| label           | string  | no       | Human-readable label                               |
| expires_at      | string  | no       | ISO 8601 UTC (default: 3072-12-31T23:59:59Z)      |
| bypass_ratelimit| boolean | no       | If true, this key bypasses admin rate limits       |

**Response:**
```json
{
  "ok": true,
  "key": "ATSM-XXXX-XXXX-XXXX"
}
```

---

### Update API key

```
PATCH /root/api-keys
Content-Type: application/json
```

**Request body:**
```json
{
  "key": "ATSM-XXXX-XXXX-XXXX",
  "label": "Updated label",
  "expires_at": "2028-12-31T23:59:59Z",
  "bypass_ratelimit": true
}
```

| Field           | Type    | Required | Description                    |
|-----------------|---------|----------|--------------------------------|
| key             | string  | yes      | API key to update             |
| label           | string  | no       | New label (omit to keep)      |
| expires_at      | string  | no       | New expiry (omit to keep)     |
| bypass_ratelimit| boolean | no       | Bypass admin rate limits (omit to keep) |

**Response:**
```json
{
  "ok": true
}
```

---

### Delete API key

```
DELETE /root/api-keys
Content-Type: application/json
```

**Request body:**
```json
{
  "key": "ATSM-XXXX-XXXX-XXXX"
}
```

**Response:**
```json
{
  "ok": true
}
```

---

## Scammers (Global Banlist)

### List scammers

```
GET /root/scammers
```

**Response:**
```json
{
  "count": 2,
  "scammers": [
    {
      "user_id": "123456789",
      "reason": "NSFW Discord Invite | Case #4015"
    }
  ]
}
```

---

### Add scammer

```
POST /root/scammers
Content-Type: application/json
```

**Request body:**
```json
{
  "user_id": "123456789",
  "reason": "NSFW Discord Invite | Case #4015",
  "report_id": "RPT_000001",
  "banned_by_user_id": "987654321"
}
```

| Field              | Type   | Required | Description                           |
|--------------------|--------|----------|---------------------------------------|
| user_id            | string | yes      | Discord user ID (min 1, max 128)      |
| reason             | string | yes      | Ban reason (min 1, max 2048)          |
| report_id          | string | no       | External report ID (max 128)          |
| banned_by_user_id  | string | no       | Discord ID of banning user (max 64)    |

**Response:**
```json
{
  "ok": true,
  "user_id": "123456789"
}
```

---

### Delete scammer (by path)

```
DELETE /root/scammers/{user_id}
```

**Response:**
```json
{
  "ok": true,
  "user_id": "123456789"
}
```

---

### Delete scammer (by body)

```
DELETE /root/scammers
Content-Type: application/json
```

**Request body:**
```json
{
  "user_id": "123456789"
}
```

**Or query param:** `?user_id=123456789`

**Response:**
```json
{
  "ok": true,
  "user_id": "123456789"
}
```

---

## URL List (Safe / Scam)

### List URLs

```
GET /root/urls
```

**Response:**
```json
{
  "ok": true,
  "count": 2,
  "items": [
    {
      "domain": "modora.xyz",
      "type": "safe",
      "reason": ""
    },
    {
      "domain": "goo.su",
      "type": "scam",
      "reason": "iplogger redirect"
    }
  ]
}
```

---

### Add or update URL

```
POST /root/urls
Content-Type: application/json
```

**Request body:**
```json
{
  "domain": "example.com",
  "type": "safe",
  "reason": ""
}
```

| Field   | Type   | Required | Description                     |
|---------|--------|----------|---------------------------------|
| domain  | string | yes      | Domain (e.g. example.com)      |
| type    | string | yes      | `"safe"` or `"scam"`           |
| reason  | string | no       | Optional reason (scam URLs)     |

**Response:**
```json
{
  "ok": true,
  "domain": "example.com"
}
```

---

### Delete URL

```
DELETE /root/urls/{domain}
```

**Response:**
```json
{
  "ok": true,
  "domain": "example.com"
}
```

---

## Staff Global Ban

### Dispatch global ban (staff signal)

```
POST /staff/signal/antiscam/global-ban
Content-Type: application/json
```

Adds a user to the global banlist and mirrors to MariaDB `global_bans` (if configured).

**Request body:**
```json
{
  "user_id": "123456789",
  "reason": "Staff decision | Case #5000",
  "report_id": "RPT_000002",
  "banned_by_user_id": "111222333",
  "source": "staff_dashboard"
}
```

| Field              | Type   | Required | Description                    |
|--------------------|--------|----------|--------------------------------|
| user_id            | string | yes      | Discord user ID                |
| reason             | string | yes      | Ban reason                     |
| report_id          | string | no       | External report ID             |
| banned_by_user_id  | string | no       | Staff Discord ID               |
| source             | string | no       | Origin (e.g. staff_dashboard)   |

**Response:**
```json
{
  "ok": true,
  "user_id": "123456789"
}
```

---

## Rate Limit Bypass

Admin endpoints are rate-limited (60 requests/min per IP). API keys with `bypass_ratelimit: true` skip this limit when their key is sent via `X-API-Key` on admin requests. Use this for automation scripts that call admin APIs.

---

## Error Codes

| Status | Description                          |
|--------|--------------------------------------|
| 400    | Bad request (invalid input)          |
| 401    | Missing or invalid API key           |
| 403    | Not master key / forbidden           |
| 404    | Resource not found                    |
| 429    | Rate limited (admin routes only)      |
| 500    | Internal server error                 |

---

## Headers

| Header        | Description                                |
|---------------|--------------------------------------------|
| X-API-Key     | Master API key (required)                  |
| X-Request-ID  | Optional request ID for correlation        |
