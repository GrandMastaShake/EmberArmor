# Security Policy

EmberArmor is a prototype and is not ready for use as a security control. Do not rely on it to protect a system. Current status is in [README.md](README.md).

## Supported versions

Only the default branch (`master`) is supported. There are no tagged releases.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting (Security tab, Report a vulnerability). Please do not put exploit details in a public issue.

## What the code does today

Checked against the code on 2026-10-02:

- Every route except `GET /ready` requires `Authorization: Bearer <EMBER_API_KEY>`. A missing, malformed or wrong key gets 401. The comparison uses `hmac.compare_digest`.
- Start-up fails unless `EMBER_API_KEY` and `EMBER_TOKEN_SECRET` are set and at least 32 characters each. A `.env` file is read only when `EMBER_ENV=development`.
- Rate limiting is in memory, per peer address, 60 requests per 60 seconds by default. Start uvicorn with `--no-proxy-headers`; without it, uvicorn takes the peer address from `X-Forwarded-For` on connections from 127.0.0.1 and a local client can sidestep the limit.
- `/docs`, `/redoc` and `/openapi.json` are switched off.
- `.gitignore` excludes `.env`, `*.pem` and `*.key`. A scan of the git history found no provider API keys and no private keys.

## What it does not do

- The detector is four regular expressions. It passes plain prompt-injection text as `SAFE`.
- `GET /v1/anchor/{id}` returns `"verified": true` for any id. Nothing is stored and nothing is checked.
- There is no audit log. `AuditLogger` exists, but no route calls it.
- JWT signing (`ember_armor/security/tokens.py`) and PBKDF2 key derivation (`ember_armor/security/crypto.py`) exist with tests, but no route uses them.
- There is no Dockerfile and no container configuration in this repository.
- `ember_proxy/` is experimental and should not be installed. Its installer adds a mitmproxy root certificate to the machine-wide Windows Trusted Root store, its launcher runs `git pull` on every start, and its scripts carry a hardcoded default API key (in `ember_proxy/addon.py`, `ember_proxy/start.bat` and `ember_proxy/install_windows.bat`). If you already ran the installer, follow the removal steps in [ember_proxy/README.md](ember_proxy/README.md).

Other known weaknesses are listed under Known issues in the README.
