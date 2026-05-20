# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✓ Current |
| 0.1.x   | ✗ EOL     |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: [billiondollarbuild@perplexity.ai](mailto:billiondollarbuild@perplexity.ai) *(competition period)*  
General contact: grandmasta1024@gmail.com

Please include:
- Description of the vulnerability and its potential impact
- Steps to reproduce
- Any proof-of-concept code (responsible disclosure only)

You will receive an acknowledgment within 48 hours and a resolution timeline within 5 business days.

## Security Architecture

### Cryptography
- API key validation: constant-time comparison to prevent timing attacks
- Token signing: JOSE/JWT with configurable algorithm (HS256 default)
- Password/secret hashing: PBKDF2-HMAC-SHA256 at **480,000 iterations** (NIST SP 800-132 compliant)
- Audit log content: SHA-256 hashed — raw inputs and outputs are **never stored**

### Deployment Hardening
- Non-root container user (UID 1000)
- Read-only root filesystem
- No privileged escalation
- Health endpoints are unauthenticated; all guard endpoints require a valid API key

### Centuria Security Audit (v1.0.0)
EmberArmor v1.0.0 was subjected to a 39-agent autonomous security audit (Centuria). Four critical vulnerabilities were identified in v0.5.0 and resolved before the v1.0.0 release:

1. **Timing oracle in API key comparison** — fixed with `hmac.compare_digest`
2. **Missing rate limit on auth endpoint** — rate limiter now applied globally before auth
3. **Audit log metadata leaking raw session IDs** — replaced with SHA-256 digests
4. **Circuit breaker state externally observable** — state response now returns opaque status codes only

## Threat Model

EmberArmor assumes:
- The guard API is **not** publicly exposed without authentication
- The underlying LLM is **untrusted** — its outputs may be adversarially influenced
- Workers/downstream agents are treated as **potentially compromised** (sanitizer-first architecture)
- The Perplexity Sonar API may be unavailable — the system fails closed, never open
