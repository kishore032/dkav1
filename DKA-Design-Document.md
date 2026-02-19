# Domain Key Authority (DKA) — Laravel Implementation Design Document

**Version:** 1.0
**Date:** February 18, 2026
**Status:** Draft

---

## 1. Overview

This document describes the design and implementation of a Domain Key Authority (DKA) as a Laravel application. A DKA collects, stores, and serves public keys of email addresses belonging to a given Internet domain. The DKA is designated by the domain via a DNS TXT record and guarantees the binding between an email ID and its public key through email-based verification.

A single Laravel codebase supports two modes of operation controlled by environment variables:

- **Domain DKA**: Accepts and serves public keys only for email addresses belonging to a specific domain.
- **Root DKA (rDKA)**: Accepts and serves public keys for email addresses from any domain.

The DKA is designed to be open-sourced with minimal dependencies for easy self-hosting.

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Laravel Application                  │
│                                                          │
│  ┌──────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │   Rawmail     │    │  Submission  │    │   Lookup   │ │
│  │  Controller   │    │     API      │    │    API     │ │
│  │  (webhook)    │    │  Controller  │    │ Controller │ │
│  └──────┬───────┘    └──────┬───────┘    └─────┬──────┘ │
│         │                   │                   │        │
│         ▼                   ▼                   │        │
│  ┌──────────────┐    ┌──────────────┐           │        │
│  │   Rawmail     │    │     DKA      │           │        │
│  │    Model      │───▶│   Service    │◀──────────┘        │
│  │ (append log)  │    │             │                    │
│  └──────────────┘    └──────┬───────┘                    │
│                             │                            │
│                      ┌──────┴───────┐                    │
│                      │   Crypto     │                    │
│                      │   Service    │                    │
│                      │ (phpseclib)  │                    │
│                      └──────────────┘                    │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────┐ │
│  │   SQLite      │  │    Redis     │  │ Symfony Mailer │ │
│  │ (key store +  │  │  (tokens)    │  │  (Mailgun)     │ │
│  │  append log)  │  │              │  │                │ │
│  └──────────────┘  └──────────────┘  └────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Components

| Component | Responsibility |
|-----------|---------------|
| **Rawmail Controller** | Receives Mailgun inbound webhook, validates Mailgun signature, deduplicates by Message-Id, stores raw email, hands off to Rawmail Model |
| **Rawmail Model** | Determines Step 1 (challenge request) vs Step 2 (submission), routes to DKA Service |
| **Submission API Controller** | Handles authenticated API challenge/submit endpoints |
| **Lookup API Controller** | Handles public read-only key lookup endpoints |
| **DKA Service** | Core business logic for register/modify/delete/dka-status commands |
| **Crypto Service** | Wraps phpseclib — key loading, algorithm detection, signature verification |
| **Symfony Mailer** | Outbound email via Mailgun (verification tokens, acknowledgements, errors) |

---

## 3. Environment Variables

```dotenv
# DKA Identity
DKA_USERNAME=dka                    # Full-flow mailbox (acknowledgements sent)
DKA_TERSE=no-reply                  # Silent mailbox (only verification emails sent)
DKA_DOMAIN=dka.keyzero.org          # The DKA's own domain (FQDN)
DKA_TARGET_DOMAIN=*                 # FQDN = domain DKA; * = rDKA (accepts any domain)

# DKA Behavior
DKA_TOKEN_TTL=900                   # Token TTL in seconds (default: 15 minutes)
DKA_UNLOCK_DELAY=60                 # Unlock delay in minutes
DKA_VERSION=1                       # DKA version identifier

# Mailgun
MG_SIGNING_KEY=                     # Mailgun webhook signing key
MG_DOMAIN=                          # Mailgun sending domain
MG_SECRET=                          # Mailgun API key (for Symfony Mailer)

# Database
DB_CONNECTION=sqlite
DB_DATABASE=/path/to/database.sqlite

# Redis
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PREFIX=dka
```

---

## 4. Database Schema (SQLite)

### 4.1 `rawmails` — Append-Only Inbound Email Log

```sql
CREATE TABLE rawmails (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT NOT NULL UNIQUE,
    from_email      TEXT NOT NULL,
    to_email        TEXT NOT NULL,
    subject         TEXT,
    timestamp       TEXT,
    spam_flag       TEXT,
    dkim_check      TEXT,
    spf_check       TEXT,
    attachment_count INTEGER DEFAULT 0,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### 4.2 `public_keys` — Key Store

```sql
CREATE TABLE public_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_id        TEXT NOT NULL,
    selector        TEXT NOT NULL,
    algorithm       TEXT,
    public_key      TEXT,
    metadata        TEXT,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(email_id, selector)
);

CREATE INDEX idx_public_keys_email_id ON public_keys(email_id);
```

**Notes:**
- `email_id`: Normalized to lowercase.
- `selector`: Lowercase alphanumeric, max 32 characters.
- `algorithm`: One of `ed25519`, `secp256r1`, `secp384r1`, `rsa2048`, `rsa3072`, `rsa4096`. Case-insensitive. NULL for metadata-only selectors (e.g., `dka-status`).
- `public_key`: PKCS#8 PEM for RSA/EC keys, PKCS#8 PEM for Ed25519 (via phpseclib). NULL for metadata-only selectors.
- `metadata`: Freeform JSON. DKA does not interpret contents (pass-through storage). Clients may store key fingerprints, purpose descriptions, crypto wallet addresses, expiration hints, etc.

**Reserved/Hidden Selectors:**
- `dka-status`: Lock/unlock control. Not returned by lookup or selectors API.
- `api`: API authentication key. Not returned by lookup or selectors API.

---

## 5. Redis Token Structure

**Key:** `dka:token:{email_id}`

**Value (JSON):**
```json
{
    "token": "cryptographically-random-string",
    "channel": "email|api",
    "created_at": "2026-02-18T12:00:00Z"
}
```

**TTL:** `DKA_TOKEN_TTL` seconds (from environment).

### 5.1 Token Rules

- Only **one token** may exist per `email_id` at any time.
- A new challenge request while a token is active is ignored.
- A token is deleted upon successful Step 2 completion.
- A failed signature verification does **not** delete the token; it survives until TTL expiry.
- A token issued via the email channel cannot be used via the API channel, and vice versa.
- Tokens are command-agnostic: the command is determined at Step 2 submission time.

---

## 6. Supported Algorithms & Cryptography

### 6.1 Supported Algorithms

| Algorithm | Key Format | Hash for Signing | PHP Library |
|-----------|-----------|-----------------|-------------|
| `ed25519` | PKCS#8 PEM | None (internal) | phpseclib `EC` |
| `secp256r1` | PKCS#8 PEM | SHA-256 | phpseclib `EC` |
| `secp384r1` | PKCS#8 PEM | SHA-384 | phpseclib `EC` |
| `rsa2048` | PKCS#8 PEM | SHA-256 | phpseclib `RSA` |
| `rsa3072` | PKCS#8 PEM | SHA-384 | phpseclib `RSA` |
| `rsa4096` | PKCS#8 PEM | SHA-512 | phpseclib `RSA` |

Algorithm identifiers are case-insensitive.

### 6.2 Key Encoding

All public keys are PKCS#8 PEM format, transmitted as **base64-encoded PEM**. The entire PEM string (including `-----BEGIN PUBLIC KEY-----` headers and line breaks) is base64-encoded. This avoids `\r\n` truncation issues across email systems and different email clients.

**Processing:** The DKA base64-decodes the `public_key` field and expects a valid PKCS#8 PEM string underneath.

### 6.3 Signature Payload

The string to be signed is a pipe-delimited concatenation:

- **Standard operations:** `{email_id}|{token}`
  - Example: `ricky21474@gmail.com|abc123`
- **API challenge request:** `{email_id}|{unix_timestamp}`
  - Example: `ricky21474@gmail.com|1739884800`

### 6.4 Crypto Service (phpseclib)

The DKA's only cryptographic operation is **signature verification**. It never encrypts or decrypts. The Crypto Service wraps three core functions:

**Algorithm Detection:**
```php
function detect_algorithm($key): ?string
```
Loads a PKCS#8 key via `PublicKeyLoader::load()`, determines the algorithm from key type and size/curve. Returns one of the six supported algorithm identifiers or `null`.

**Signature Verification:**
```php
function zc_verify_raw($data, $signature, $public_key): ?bool
```
Pre-hashes the data according to the algorithm's hash function (except Ed25519), then verifies the base64-decoded signature against the public key. Returns `true`, `false`, or `null` on error.

**Key Generation (for testing/reference):**
```php
function zc_asymmetric_keys($algo): ?object
```
Generates a key pair for the specified algorithm. Returns `{secret_key, public_key}` both in PKCS#8 PEM format.

---

## 7. Inbound Email Flow (Mailgun Webhook)

### 7.1 Rawmail Controller

The Rawmail Controller receives POST requests from Mailgun's inbound webhook at a configured route (e.g., `/webhook/mailgun`).

**Processing steps:**

1. **Validate payload**: Reject if `Message-Id` is missing.
2. **Deduplicate**: Check `rawmails` table for existing `Message-Id`. Return `200` if duplicate.
3. **Verify Mailgun signature**: HMAC-SHA256 of `timestamp + token` against `MG_SIGNING_KEY`. Return `401` if invalid.
4. **Parse From**: Extract sender email via `eparse()`. Reject if unparseable.
5. **Domain check**: If `DKA_TARGET_DOMAIN` is not `*`, verify sender's domain matches. Reject if mismatch.
6. **Parse recipient**: Extract recipient via `eparse()`. Reject if recipient mailbox is not `DKA_USERNAME` or `DKA_TERSE`.
7. **Store**: Create `Rawmail` record (append-only log), store raw POST data and attachments to disk.
8. **Hand off**: Pass to Rawmail Model for processing.

**Verbose vs Terse mode:**
- Recipient matches `DKA_USERNAME` → verbose mode (acknowledgements, confirmations, error messages sent).
- Recipient matches `DKA_TERSE` → terse mode (only verification token emails sent).

### 7.2 Rawmail Model — Step 1 vs Step 2 Routing

The Rawmail Model examines the stored email to determine the processing path:

**Step 1 Detection (Challenge Request):**
- No active token exists in Redis for this `email_id`
- Action: Check DKIM (`X-Mailgun-Dkim-Check-Result`).
  - If `Pass`: Generate token, store in Redis with channel `email`, send token to sender.
  - If not `Pass`: Send error (verbose) or silently ignore (terse).

**Step 2 Detection (Submission):**
- An active token exists in Redis for this `email_id` with channel `email`
- Action: Parse subject line to determine command, extract and parse JSON attachment, route to DKA Service.

### 7.3 Email Subject Lines

| Subject (case-insensitive) | Command Type | Step 2 Attachment |
|---------------------------|-------------|-------------------|
| `register` | Key registration | JSON (single or batch array) |
| `modify` | Key modification | JSON (single) |
| `delete` | Key deletion | JSON (single) |
| `dka-status=locked` | Lock account | JSON (minimal) |
| `dka-status=open` | Unlock account | JSON (minimal) |
| Any other subject | Challenge request (Step 1) | Ignored |

---

## 8. Email Commands — Detailed Flows

### 8.1 `register` — Create New Key

**Pre-condition:** Selector must NOT already exist for this `email_id`.

**Step 1:** Sender emails DKA with any subject. DKA verifies DKIM, generates token, returns token via email.

**Step 2:** Sender emails with Subject: `register`. Attachment is a JSON file:

```json
{
    "email_id": "user@example.com",
    "selector": "default",
    "algorithm": "ed25519",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "metadata": {},
    "token": "the-token-from-step-1",
    "signature": "base64-encoded-signature-over-email_id|token"
}
```

**DKA Processing:**
1. Verify active token exists for `email_id` with channel `email`.
2. Verify token matches.
3. Check `dka-status` for `email_id` — reject if locked.
4. Verify selector does not already exist.
5. Validate selector format (lowercase alphanumeric, ≤32 chars).
6. Load public key, run `detect_algorithm()`, cross-check against `algorithm` field.
7. Verify `signature` against submitted `public_key` using `zc_verify_raw("email_id|token", signature, public_key)`.
8. Store key in `public_keys` table.
9. Delete token from Redis.
10. Send acknowledgement (verbose) or silently succeed (terse).

### 8.2 `register` — Batch (Email Only)

**Step 2 attachment** is a JSON array of registration objects:

```json
[
    {
        "email_id": "user@example.com",
        "selector": "default",
        "algorithm": "ed25519",
        "public_key": "...",
        "metadata": {},
        "token": "same-token",
        "signature": "sign(email_id|token) with default's private key"
    },
    {
        "email_id": "user@example.com",
        "selector": "signing",
        "algorithm": "rsa4096",
        "public_key": "...",
        "metadata": {},
        "token": "same-token",
        "signature": "sign(email_id|token) with signing's private key"
    }
]
```

**Rules:**
- All entries must share the same `email_id` (must match the sender).
- All entries must share the same `token`.
- Each entry must reference a different `selector`.
- Each entry is validated independently — if one fails, others can still succeed.
- The token is deleted from Redis after processing the batch (regardless of individual success/failure).

### 8.3 `modify` — Replace Existing Key

**Pre-condition:** Selector MUST already exist for this `email_id`.

**Step 2 attachment:**

```json
{
    "email_id": "user@example.com",
    "selector": "default",
    "algorithm": "rsa4096",
    "public_key": "new-public-key-PEM",
    "metadata": {},
    "token": "the-token",
    "old_signature": "sign(email_id|token) with OLD private key",
    "new_signature": "sign(email_id|token) with NEW private key"
}
```

**DKA Processing:**
1. Verify active token, channel, token match.
2. Check `dka-status` — reject if locked.
3. Verify selector exists for `email_id`.
4. Load new public key, run `detect_algorithm()`, cross-check.
5. Verify `old_signature` against the **stored** public key.
6. Verify `new_signature` against the **submitted** (new) public key.
7. Replace key in `public_keys` table.
8. Delete token from Redis.
9. Acknowledgement (verbose).

### 8.4 `delete` — Remove Existing Key

**Pre-condition:** Selector MUST already exist for this `email_id`.

**Step 2 attachment:**

```json
{
    "email_id": "user@example.com",
    "selector": "default",
    "token": "the-token",
    "signature": "sign(email_id|token) with EXISTING private key"
}
```

**DKA Processing:**
1. Verify active token, channel, token match.
2. Check `dka-status` — reject if locked.
3. Verify selector exists for `email_id`.
4. Verify `signature` against the **stored** public key.
5. Hard-delete key from `public_keys` table.
6. Delete token from Redis.
7. Acknowledgement (verbose).

### 8.5 `dka-status=locked` — Lock Account

**No signature required.** Mailbox control (DKIM + token) is sufficient.

**Step 2 attachment:**

```json
{
    "email_id": "user@example.com",
    "token": "the-token"
}
```

**DKA Processing:**
1. Verify active token, channel `email`, token match.
2. Create or update `dka-status` selector row: `metadata = {"status": "locked"}`.
3. Delete token from Redis.
4. Acknowledgement (verbose).

**Effect:** All register/modify/delete operations rejected for this `email_id` (both email and API channels). Only `dka-status=open` is accepted. The DKA continues to serve any existing keys via the public lookup API while locked.

### 8.6 `dka-status=open` — Unlock Account (Delayed)

**Email only. No signature required.**

**Step 2 attachment:**

```json
{
    "email_id": "user@example.com",
    "token": "the-token"
}
```

**DKA Processing:**
1. Verify active token, channel `email`, token match.
2. Update `dka-status` selector row: `metadata = {"status": "locked", "unlocks_at": "<now + DKA_UNLOCK_DELAY minutes>"}`.
3. Delete token from Redis.
4. Acknowledgement (verbose): "Your account will be unlocked at {unlocks_at}."

**Unlock evaluation (lazy):** On any incoming operation for an `email_id`, the DKA checks the `dka-status` row:
- No row or `status = open` → proceed.
- `status = locked`, no `unlocks_at` → reject (except `dka-status=open`).
- `status = locked`, `unlocks_at` in the past → lazily flip to `{"status": "open"}`, proceed.
- `status = locked`, `unlocks_at` in the future → still locked, reject.

**Edge case:** If a `dka-status=locked` request arrives while an unlock is pending (`unlocks_at` is set but in the future), it is ignored. The unlock will proceed at the scheduled time. The user can re-lock after unlock completes.

---

## 9. API Endpoints

### 9.1 Public Lookup API (Unauthenticated)

| Endpoint | Method | Parameters | Description |
|----------|--------|-----------|-------------|
| `/api/v1/lookup` | GET | `email` (required), `selector` (optional) | Get public key |
| `/api/v1/selectors` | GET | `email` (required) | List non-hidden selectors |
| `/api/v1/version` | GET | — | DKA version info |
| `/api/v1/apis` | GET | — | List supported endpoints |

**`GET /api/v1/lookup?email={email_id}`**

Returns the `default` selector's public key:

```json
{
    "email_id": "user@example.com",
    "selector": "default",
    "algorithm": "ed25519",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...",
    "metadata": {},
    "updated_at": "2026-02-18T12:00:00Z"
}
```

**`GET /api/v1/lookup?email={email_id}&selector={selector}`**

Returns the specified selector's public key. Returns `404` if the selector is not found or is a hidden selector (`dka-status`, `api`).

**`GET /api/v1/selectors?email={email_id}`**

```json
{
    "email_id": "user@example.com",
    "selectors": ["default", "signing", "cw"]
}
```

Hidden selectors (`dka-status`, `api`) are excluded. Returns `404` if `email_id` has no public keys.

**`GET /api/v1/version`**

```json
{
    "dka_version": 1,
    "domain": "dka.keyzero.org",
    "mode": "rdka"
}
```

**`GET /api/v1/apis`**

```json
{
    "endpoints": [
        {"method": "GET", "path": "/api/v1/lookup", "params": ["email", "selector?"]},
        {"method": "GET", "path": "/api/v1/selectors", "params": ["email"]},
        {"method": "GET", "path": "/api/v1/version"},
        {"method": "GET", "path": "/api/v1/apis"},
        {"method": "POST", "path": "/api/v1/challenge"},
        {"method": "POST", "path": "/api/v1/submit"}
    ]
}
```

**Error responses:**

| Condition | HTTP Status |
|-----------|-------------|
| Key found | 200 |
| Email/selector not found | 404 |
| Hidden selector requested | 404 (do not leak existence) |
| Domain mismatch (DKA mode, not rDKA) | 403 |

### 9.2 Submission API (Authenticated)

The Submission API requires the `email_id` to have an `api` selector registered (via the email flow). All requests are authenticated with a signature from the `api` selector's private key.

**`POST /api/v1/challenge`**

Request a token for subsequent submission.

```json
{
    "email_id": "user@example.com",
    "api_signature": "sign(email_id|unix_timestamp) with api-selector private key",
    "unix_timestamp": 1739884800
}
```

**Processing:**
1. Verify `api` selector exists for `email_id`.
2. Verify `unix_timestamp` is within ±5 minutes of server time.
3. Verify `api_signature` against stored `api` selector public key, signing payload: `{email_id}|{unix_timestamp}`.
4. Check no active token exists for `email_id` — reject if one does.
5. Generate token, store in Redis with channel `api`.
6. Return token in response.

**Response:**
```json
{
    "token": "cryptographic-random-string",
    "expires_in": 900
}
```

**`POST /api/v1/submit`**

Submit a key operation.

**Register via API:**
```json
{
    "command": "register",
    "email_id": "user@example.com",
    "selector": "default",
    "algorithm": "ed25519",
    "public_key": "...",
    "metadata": {},
    "token": "the-token",
    "signature": "sign(email_id|token) with new private key",
    "api_signature": "sign(email_id|token) with api-selector private key"
}
```

**Modify via API:**
```json
{
    "command": "modify",
    "email_id": "user@example.com",
    "selector": "default",
    "algorithm": "rsa4096",
    "public_key": "new-public-key",
    "metadata": {},
    "token": "the-token",
    "old_signature": "sign(email_id|token) with OLD private key",
    "new_signature": "sign(email_id|token) with NEW private key",
    "api_signature": "sign(email_id|token) with api-selector private key"
}
```

**Delete via API:**
```json
{
    "command": "delete",
    "email_id": "user@example.com",
    "selector": "default",
    "token": "the-token",
    "signature": "sign(email_id|token) with existing private key",
    "api_signature": "sign(email_id|token) with api-selector private key"
}
```

**All API submissions** require `api_signature` in addition to the command-specific signatures. The `api_signature` signs the same payload (`email_id|token`) as the other signatures, but uses the `api` selector's private key.

**Note:** The `api` selector can only be registered, modified, or deleted via the email flow. It cannot be managed via the API (circular dependency).

**Note:** `dka-status` commands are email-only and are not available via the Submission API.

---

## 10. Race Condition Handling

### 10.1 Token Exclusivity

- Only one token per `email_id` in Redis at any time.
- A new challenge request (email or API) while a token is active is ignored.
- Token stores its channel (`email` or `api`); cross-channel use is rejected.
- Token is command-agnostic; the command is determined at Step 2.

### 10.2 Token Lifecycle

| Event | Token State |
|-------|------------|
| Challenge request, no active token | Created with TTL |
| Challenge request, active token exists | Ignored |
| Step 2 success | Token deleted |
| Step 2 failure (bad signature) | Token survives until TTL |
| TTL expires | Token auto-deleted by Redis |

### 10.3 Message Deduplication

Mailgun may redeliver webhooks. The `message_id` field is stored in the `rawmails` table with a unique constraint. Duplicate Message-Ids return `200` immediately without processing.

### 10.4 Database-Level Safety

Since there is only one active token per `email_id` and tokens are channel-locked, concurrent database writes for the same `email_id` cannot occur through normal flows.

---

## 11. `dka-status` Lock/Unlock Behavior

| Current State | Incoming Command | Result |
|--------------|-----------------|--------|
| No `dka-status` row | Any operation | Proceed (treated as open) |
| `status: open` | register/modify/delete | Proceed |
| `status: locked` (no `unlocks_at`) | register/modify/delete | Reject |
| `status: locked` (no `unlocks_at`) | `dka-status=open` | Schedule unlock |
| `status: locked` (`unlocks_at` in future) | register/modify/delete | Reject |
| `status: locked` (`unlocks_at` in future) | `dka-status=locked` | Ignore (let unlock proceed) |
| `status: locked` (`unlocks_at` in past) | Any operation | Lazily flip to open, proceed |

---

## 12. Hidden Selectors

The following selectors are internal to the DKA and are never exposed through the public lookup or selectors API:

| Selector | Purpose | Manageable Via |
|----------|---------|---------------|
| `dka-status` | Account lock/unlock | Email only |
| `api` | API authentication | Email only |

Requests to look up a hidden selector return `404` (identical to "not found") to prevent leaking their existence.

---

## 13. Dependencies

| Package | Purpose |
|---------|---------|
| **Laravel** | Application framework |
| **phpseclib** | Pure PHP cryptography (RSA, EC, Ed25519) — no PHP extension dependencies |
| **predis/predis** | Redis client for token management |
| **SQLite** | Database (single file, no server) |
| **Symfony Mailer** | Outbound email via Mailgun |

No other runtime dependencies. The DKA is designed for minimal footprint and easy self-hosting.

---

## 14. DNS Configuration (Reference)

For a domain `example.com` to designate its DKA:

```
dka.example.com.    IN  TXT    "https://dka.example.com; v1"
dka.example.com.    IN  MX     mxa.mailgun.org.
dka.example.com.    IN  A      <IP address of DKA server>
```

The TXT record specifies the DKA URL and version number. The MX record points to Mailgun for inbound email handling.

---

## 15. Laravel Project Structure

```
app/
├── Http/
│   ├── Controllers/
│   │   ├── RawmailController.php       # Mailgun webhook receiver
│   │   ├── LookupController.php        # Public key lookup API
│   │   └── SubmissionController.php    # Authenticated submission API
│   └── Middleware/
│       └── VerifyMailgunSignature.php   # (optional, or inline in controller)
├── Models/
│   ├── Rawmail.php                     # Inbound email log + routing logic
│   └── PublicKey.php                   # Key store model
├── Services/
│   ├── DkaService.php                  # Core business logic
│   ├── CryptoService.php              # phpseclib wrapper
│   └── TokenService.php               # Redis token management
├── Helpers/
│   └── eparse.php                      # Email address parser
routes/
├── api.php                             # API routes
└── web.php                             # Webhook route
database/
└── migrations/
    ├── create_rawmails_table.php
    └── create_public_keys_table.php
config/
└── dka.php                             # DKA-specific config from env
```

---

## 16. Route Definitions

```php
// routes/web.php
Route::post('/webhook/mailgun', [RawmailController::class, 'receive']);

// routes/api.php (prefix: /api/v1)
Route::prefix('v1')->group(function () {
    // Public lookup
    Route::get('/lookup',    [LookupController::class, 'lookup']);
    Route::get('/selectors', [LookupController::class, 'selectors']);
    Route::get('/version',   [LookupController::class, 'version']);
    Route::get('/apis',      [LookupController::class, 'apis']);

    // Authenticated submission
    Route::post('/challenge', [SubmissionController::class, 'challenge']);
    Route::post('/submit',    [SubmissionController::class, 'submit']);
});
```

---

## 17. Future Considerations (V2+)

- **Domain Trust Anchor (DTA)**: A DNSSEC-secured DKA at a fixed location that registers signing keys of DKAs. DKAs sign their API outputs; recipients verify via DTA. Current V1 design is DTA-compatible with no breaking changes.
- **Rate limiting / throttling** on lookup API (per IP, per email_id queried).
- **Authentication on lookup API** for sensitive use cases.
- **Multi-tenancy** (single instance serving multiple domains).
- **rDKA federation** (rDKA checks domain's DKA before its own store).
- **X.509 certificate issuance** (DKA as intermediate CA).
- **Additional verification levels** (2FA, social verification).
- **Batch modify/delete** via email.
- **Web UI** for key management (beyond informational).

---

## Appendix A: Tested PHP Code Reference

### A.1 Email Address Parser (`eparse`)

```php
define('EMAIL_NAME', '(.*)');
define('MAILBOX', '\s*([a-z][a-z0-9\'-.]*)\s*');
define('HOST', '([a-z][a-z0-9-]*\.)*([a-z][a-z0-9-]+\.[a-z]+)');

function eparse($rfc)
{
    if (gettype($rfc) != 'string' || $rfc == '') return null;
    $email_object = new stdClass;
    if (strpos($rfc, '>')) {
        preg_match('/^' . EMAIL_NAME . '<' . MAILBOX . '@(' . HOST . ')' . '\s*>\s*$/i', $rfc, $m);
        if (!$m) return null;
        $email_object->name = trim($m[1]);
    } else {
        preg_match('/^' . MAILBOX . '@(' . HOST . ')' . '\s*$/i', $rfc, $m);
        if (!$m) return null;
        array_unshift($m, null);
        $email_object->name = '';
    }
    $email_object->mailbox = strtolower($m[2]);
    $email_object->host = strtolower($m[3]);
    $email_object->email = $email_object->mailbox . '@' . $email_object->host;
    $email_object->domain = strtolower($m[5]);
    return $email_object;
}
```

### A.2 Key Generation

```php
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\RSA;

function zc_asymmetric_keys($algo): ?object
{
    switch (strtolower($algo)) {
        case 'ed25519': case 'secp256r1': case 'secp384r1':
            $keypair = EC::createKey($algo);
            break;
        case 'rsa2048': case 'rsa3072': case 'rsa4096':
            $keypair = RSA::createKey((int) substr($algo, 3, 4));
            break;
        default:
            return null;
    }
    return (object) [
        'secret_key' => $keypair->toString('pkcs8'),
        'public_key' => $keypair->getPublicKey()->toString('pkcs8')
    ];
}
```

### A.3 Algorithm Detection

```php
use phpseclib3\Crypt\PublicKeyLoader;

function detect_algorithm($key): ?string
{
    try {
        $key = PublicKeyLoader::load($key);
    } catch (Exception $e) {
        return null;
    }
    if (!($key instanceof PublicKey || $key instanceof PrivateKey
        || $key instanceof RSAPublicKey || $key instanceof RSAPrivateKey)) {
        return null;
    }
    if ($key && $key->getLoadedFormat() != 'PKCS8') {
        return null;
    }
    if ($key instanceof RSAPublicKey || $key instanceof RSAPrivateKey) {
        $key_length = $key->getLength();
        if (in_array($key_length, [2048, 3072, 4096])) {
            return 'rsa' . $key_length;
        } else {
            return null;
        }
    }
    $curve = method_exists($key, 'getCurve') ? strtolower($key->getCurve()) : '';
    if (in_array($curve, ['ed25519', 'secp256r1', 'secp384r1'])) {
        return $curve;
    } else {
        return null;
    }
}
```

### A.4 Signature Signing and Verification

```php
function zc_sign_raw($data, $secret_key): ?string
{
    $secret_key = PublicKeyLoader::load($secret_key);
    if (!($secret_key instanceof PrivateKey) && !($secret_key instanceof RSAPrivateKey)) return null;
    if ($secret_key instanceof RSAPrivateKey) {
        $hash_algs = [4096 => 'sha512', 3072 => 'sha384', 2048 => 'sha256'];
        $hash_alg = $hash_algs[$secret_key->getLength()];
    } else {
        $hash_algs = ['Ed25519' => null, 'secp256r1' => 'sha256', 'secp384r1' => 'sha384'];
        $hash_alg = $hash_algs[$secret_key->getCurve()];
    }
    if ($hash_alg) {
        $data = hash($hash_alg, $data, true);
    }
    return base64_encode($secret_key->sign($data));
}

function zc_verify_raw($data, $signature, $public_key): ?bool
{
    $public_key = PublicKeyLoader::load($public_key);
    if (!($public_key instanceof PublicKey) && !($public_key instanceof RSAPublicKey)) return null;
    if ($public_key instanceof RSAPublicKey) {
        $hash_algs = [4096 => 'sha512', 3072 => 'sha384', 2048 => 'sha256'];
        $hash_alg = $hash_algs[$public_key->getLength()];
    } else {
        $hash_algs = ['Ed25519' => null, 'secp256r1' => 'sha256', 'secp384r1' => 'sha384'];
        $hash_alg = $hash_algs[$public_key->getCurve()];
    }
    if ($hash_alg) {
        $data = hash($hash_alg, $data, true);
    }
    try {
        return $public_key->verify($data, base64_decode($signature));
    } catch (Exception $e) {
        return null;
    }
}
```
