# EmberArmor Proxy

Universal AI traffic interceptor for Windows. One installer, works for anyone — downloads EmberArmor directly from GitHub, installs everything, and creates a desktop shortcut.

Sits between your browser and every AI API you use — Claude, Perplexity, Kimi, Gemini, OpenAI — and runs every prompt through EmberArmor's enforcement engine in real time.

## Setup (anyone, any machine)

**Requirements:** Python 3.11+ · Git

1. **Download just this file:**
   [`install_windows.bat`](https://raw.githubusercontent.com/GrandMastaShake/EmberArmor/master/ember_proxy/install_windows.bat)

2. **Right-click → Run as Administrator**

   The installer will:
   - Clone the full EmberArmor repo to `%USERPROFILE%\EmberArmor`
   - Install all Python dependencies
   - Generate and trust the mitmproxy CA cert in Windows
   - Create an **EmberArmor Proxy** shortcut on your Desktop

3. **Add your Perplexity API key** to `%USERPROFILE%\EmberArmor\.env`:
   ```
   PERPLEXITY_API_KEY=your-key-here
   ```

4. **Double-click the Desktop shortcut** — done.

---

## Daily use

| Action | How |
|--------|-----|
| Start | Double-click **EmberArmor Proxy** on Desktop |
| Dashboard | `http://localhost:7070` (opens automatically) |
| Stop | Close the terminal window |

The system proxy is set automatically on start and restored on stop. Everything else — browsers, VS Code, API scripts — routes through EmberArmor without any configuration.

---

## Intercepted endpoints

| Host | Service |
|------|---------|
| `api.anthropic.com` | Claude |
| `api.perplexity.ai` | Perplexity / Sonar |
| `api.moonshot.ai` | Kimi |
| `generativelanguage.googleapis.com` | Gemini |
| `api.openai.com` | OpenAI + compatible |

Everything else passes through untouched.

---

## Modes

**Monitor mode (default)** — logs everything, blocks nothing. Good for real-world tuning.

**Blocking mode** — UNSAFE decisions return a 403 to the calling app.

To enable blocking, edit `%USERPROFILE%\EmberArmor\ember_proxy\.env`:
```
BLOCK_ON_UNSAFE=true
```
Then restart.

---

## Dashboard

`http://localhost:7070` — auto-refreshes every 3 seconds.

- Total checks · SAFE / REVIEW / UNSAFE counts
- Average enforcement latency
- Live feed: host, decision, score, latency, prompt preview (first 120 chars)
- `/api/log` — raw JSON for scripting

---

## Files

| File | Purpose |
|------|---------|
| `install_windows.bat` | One-time setup — clones repo, installs deps, trusts cert, creates shortcut |
| `start.bat` | Starts EmberArmor API + proxy, sets system proxy, opens dashboard |
| `stop.bat` | Emergency stop — kills processes, restores system proxy |
| `addon.py` | mitmproxy interceptor + status dashboard server |
| `.env` | Local config (gitignored) |

---

## Uninstall

```bat
certutil -delstore Root "mitmproxy"
```
Then delete `%USERPROFILE%\EmberArmor` and the Desktop shortcut.
