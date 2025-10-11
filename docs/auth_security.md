# Authentication & Security

## Supported Auth Modes
- Basic Auth: Static username/password supplied at server startup (HTTP Basic challenge).
- Bearer Tokens: List of opaque tokens accepted in `Authorization: Bearer <tok>` header.
- Session Cookie (Form Login): Bcrypt password hash configured; /login form issues signed cookie.

Multiple methods can coexist; successful validation on any path suffices.

## Session Cookie Design
Cookie value structure (Base64 URL encoded):
```
v1|<exp_unix>|<user>|<nonce_b64>|<hmac_sig_b64>
```
- HMAC-SHA256 signature over payload (without signature) using `sessionSecret`.
- Nonce random 16 bytes prevents token prediction; replay within TTL acceptable by design (no rotation list).
- TTL defaults to 12h; adjustable via SetLogin.

## Password Storage
Bcrypt hash created by `logtool-pwhash` utility; server stores hash string and compares with `bcrypt.CompareHashAndPassword`.

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

