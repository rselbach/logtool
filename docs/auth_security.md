# Authentication & Security

## Supported Auth Modes
- **GitHub OAuth** (recommended): Interactive browser login via GitHub; issues signed session cookie. Supports any GitHub account.
- **Apple OAuth**: Interactive browser login via Sign in with Apple; issues signed session cookie. Uses ES256 client secrets and RS256 id_token validation.
- **Bearer Tokens**: List of opaque tokens accepted in `Authorization: Bearer <tok>` header. Ideal for API clients and automation.
- **Basic Auth**: Static username/password supplied at server startup (HTTP Basic challenge). Alternative for API clients.

Multiple methods can coexist; successful validation on any path suffices.

## GitHub OAuth Login

### Overview
GitHub OAuth provides secure, password-less authentication for interactive users. The server never stores user credentials.

### Flow
1. User visits protected endpoint → redirected to `/login`
2. `/login` page shows "Sign in with GitHub" button
3. User clicks button → redirected to GitHub OAuth authorize page
4. User approves access → GitHub redirects to `/auth/github/callback`
5. Server exchanges authorization code for access token (with PKCE)
6. Server fetches user info from GitHub API
7. Server issues signed session cookie with `gh:<github_login>`
8. User redirected to original destination

### Security Features
- **PKCE (S256)**: Proof Key for Code Exchange prevents authorization code interception attacks
- **State parameter**: CSRF protection via short-lived cookie (5 minute expiry)
- **No stored credentials**: Server never sees or stores GitHub passwords
- **Minimal scopes**: Only requests `user:email` scope
- **No user persistence**: User data not stored in database

### Setup

#### 1. Create GitHub OAuth App
1. Go to GitHub Settings → Developer settings → OAuth Apps → New OAuth App
2. Fill in:
   - **Application name**: Logtool (or your preferred name)
   - **Homepage URL**: `https://your-domain.com`
   - **Authorization callback URL**: `https://your-domain.com/auth/github/callback` (or with `/monitor` prefix if behind reverse proxy)
3. Click "Register application"
4. Note the **Client ID**
5. Generate a new **Client Secret**

#### 2. Configure Server
Set environment variables (typically in `/etc/logtool/server.env`):
```bash
GITHUB_CLIENT_ID=your_client_id_here
GITHUB_CLIENT_SECRET=your_client_secret_here
GITHUB_CALLBACK_URL=https://your-domain.com/auth/github/callback

# Session configuration
LOGTOOL_SESSION_SECRET=base64_encoded_random_32_bytes
LOGTOOL_SESSION_TTL=12h
LOGTOOL_SECURE_COOKIES=true  # Required for HTTPS deployments
```

#### 3. Generate Session Secret
```bash
openssl rand -base64 32
```

#### 4. Configure Email Allowlist (Required)
OAuth authentication requires an explicit email allowlist. Without this configuration, all login attempts will be denied for security.

```bash
# Allow specific email addresses
LOGTOOL_EMAIL_ALLOWLIST=alice@example.com,bob@example.com

# Allow wildcard patterns (single * supported)
LOGTOOL_EMAIL_ALLOWLIST=*@example.com  # All users from example.com
LOGTOOL_EMAIL_ALLOWLIST=admin@*        # Any admin@ email

# Combine both
LOGTOOL_EMAIL_ALLOWLIST=alice@corp.com,*@trusted.com
```

**Pattern matching:**
- Single `*` wildcard supported at start or end
- Patterns like `*@*.example.com` not supported (only first/last part used)
- Email matching is case-insensitive

## Apple OAuth Login

### Setup
1. Create Services ID at https://developer.apple.com/account/resources/identifiers
2. Create Sign in with Apple Key and download .p8 file
3. Configure callback URL: `https://your-domain.com/auth/apple/callback`
4. Set environment variables: `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY_FILE` (or `APPLE_PRIVATE_KEY`), `APPLE_CALLBACK_URL`

### Security Features
- **PKCE (S256)**: Same as GitHub
- **Client Secret**: Generated as ES256 JWT signed with your Apple private key (5 min TTL)
- **id_token Validation**: RS256 signature verified against Apple JWKS; iss, aud, exp, nonce claims validated
- **No user persistence**: User identified by stable `sub` claim; stored as `ap:<sub>` in session

### Logging
Apple OAuth events logged at info level:
- `apple_login_started`, `apple_login_success`, `apple_callback_error`, `apple_token_exchange_error`, `apple_idtoken_verify_error`, `apple_nonce_mismatch`

### Logging (GitHub and Apple)
OAuth events are logged at info level. No secrets (tokens, codes, verifiers) are logged.

## Session Cookie Design
Cookie value structure (Base64 URL encoded):
```
v2|<exp_unix>|<user_b64>|<email_b64>|<nonce_b64>|<hmac_sig_b64>
```
- HMAC-SHA256 signature over payload (without signature) using `sessionSecret`.
- Nonce random 16 bytes prevents token prediction; replay within TTL acceptable by design (no rotation list).
- TTL defaults to 12h; configurable via `LOGTOOL_SESSION_TTL`.
- User field format: `gh:<github_login>` for GitHub OAuth, `ap:<sub>` for Apple OAuth.
- Cookies set with `HttpOnly`, `SameSite=Lax`, and `Secure` (when `LOGTOOL_SECURE_COOKIES=true`).

## Bearer Tokens
Exact string match after trimming. Token secrets not hashed; recommend providing high-entropy random values.

## Basic Auth
Standard challenge/response; realm set to "Logtool".

## Authorization Scope
Single global scope: any authenticated principal can access all endpoints. No per-host or per-action ACL.

## CORS
Optional wildcard CORS (`*`) for GET/OPTIONS with `Content-Type, Authorization` headers allowed. Should be disabled for private deployments unless cross-origin dashboard embedding required.

## IP Privacy Policies
Applied on ingestion only; stored remote_addr/XFF may be masked/hashed/dropped to reduce sensitivity of retained logs. Policy selection tradeoffs:
- store: Maximum utility (full IP analytics) but least private.
- mask: Retains subnet-level insights, minimizes exact tracking.
- hash: Enables unique counting without revealing originals (salt strengthens unlinkability across deployments if kept secret).
- drop: Maximizes privacy; reduces uniqueness metrics (unique_remote may become low or zero).

## Data Integrity
Unique index on raw_line mitigates accidental duplicate ingestion. No tamper-proofing beyond SQLite file system semantics.

## Potential Threats & Mitigations
- Log Injection (malicious quotes/newlines): Lines stored raw; queries avoid constructing SQL with raw_line, so risk limited. Consider sanitizing if exposing raw_line later.
- Cookie Theft: Cookie is HttpOnly; enabling HTTPS via reverse proxy (nginx config provided) recommended.
- Timing Attacks: HMAC verification uses constant-time comparison (hmac.Equal).
- User-Agent / Path Overflows: No length checks presently; SQLite handles large TEXT but extremely long inputs could bloat DB.

## Hardening Recommendations
- Run behind reverse proxy terminating TLS.
- Restrict file permissions on SQLite DB.
- Use hash or drop IP policy if distributing analytics externally.
- Periodically rotate bearer tokens/session secret (restart server).
- Keep build dependencies updated (go mod tidy & update periodically).

