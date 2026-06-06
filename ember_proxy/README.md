# EmberArmor Proxy

Universal AI traffic interceptor for Windows. Sits between your browser/apps and every AI API you use — Claude, Perplexity, Kimi, Gemini, OpenAI — and runs every prompt through the EmberArmor enforcement engine in real time.

## What it does

- Intercepts all outbound AI API traffic transparently
- Runs each prompt through EmberArmor (DissonanceDetector + EnsembleConductor + Sonar)
- Logs every decision with full latency telemetry
- Shows a live dashboard at `http://localhost:7070`
- Starts in **monitor mode** (log everything, block nothing) — flip `BLOCK_ON_UNSAFE=true` when you're confident in the tuning

## Intercepted endpoints

| Host | Service |
|------|---------|
| `api.anthropic.com` | Claude |
| `api.perplexity.ai` | Perplexity / Sonar |
| `api.moonshot.ai` | Kimi |
| `generativelanguage.googleapis.com` | Gemini |
| `api.openai.com` | OpenAI + compatible |

Everything else passes through untouched.

## Setup (one time)

1. **Place this folder** next to your `EmberArmor` repo:
   ```
   your-projects/
   ├── EmberArmor/
   ├── EmberHoneypot/
   ├── Corporeus/
   ├── EmberBench/
   └── ember_proxy/      ← this folder
   ```

2. **Set your EmberArmor API key** in `.env`:
   ```
   EMBER_API_KEY=ember-proxy-internal-key
   ```
   And make sure the same key is set in your EmberArmor config.

3. **Run the installer** (once, as Administrator):
   ```
   Right-click install_windows.bat → Run as administrator
   ```
   This installs the mitmproxy CA cert into Windows Trusted Root so your browser trusts the proxy's TLS.

4. **Set your Perplexity API key** in EmberArmor's env:
   ```
   PERPLEXITY_API_KEY=your-key-here
   ```
   (Required for Sonar consensus agent)

## Daily use

**Start:**
```
Double-click start.bat
```
Opens the dashboard automatically. Use your AI tools normally.

**Stop:**
```
Double-click stop.bat
   — or —
Close the start.bat window
```
System proxy is restored automatically on exit.

## Dashboard

`http://localhost:7070` — auto-refreshes every 3 seconds.

Shows:
- Total checks, SAFE / REVIEW / UNSAFE counts
- Average enforcement latency
- Live feed of last 50 intercepts with host, decision, score, latency, prompt preview

## Tuning mode → Blocking mode

Once you've run it for a week and the REVIEW/UNSAFE decisions look right, flip the switch:

Edit `.env`:
```
BLOCK_ON_UNSAFE=true
```

Or edit `addon.py` line:
```python
BLOCK_ON_UNSAFE = True
```

Restart `start.bat`. Now UNSAFE decisions return a 403 to the calling app instead of passing through.

## Adding new AI endpoints

Edit the `AI_HOSTS` set in `addon.py`:
```python
AI_HOSTS = {
    "api.anthropic.com",
    "api.your-new-service.com",   # add here
    ...
}
```

## Files

| File | Purpose |
|------|---------|
| `addon.py` | mitmproxy interceptor + status dashboard server |
| `start.bat` | Starts EmberArmor API + proxy, sets system proxy |
| `stop.bat` | Kills everything, restores system proxy |
| `install_windows.bat` | One-time: installs cert, pip deps |
| `.env` | Config (API key, ports, block mode) |

## Latency notes

Current EmberArmor enforcement averages **860ms**. This is acceptable for most chat/coding use. The audit log tracks every request's latency — after real-world usage you'll see the distribution and can decide:

- **Fast-path**: Skip full Sonar consensus for short/routine prompts, only invoke it above a length or pattern threshold
- **Async logging**: Pass through immediately, check in background, flag after the fact
- **Model swap**: Use a lighter local model for first-pass filtering

These optimizations are best done with real data, which is exactly why we start in monitor mode.
