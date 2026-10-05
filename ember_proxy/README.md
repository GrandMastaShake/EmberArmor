# EmberArmor Proxy

**Experimental sketch. It does not work.** Status as of 2026-10-05.

This folder holds a mitmproxy addon (`addon.py`) meant to send prompts bound for AI API hosts through the EmberArmor check endpoint. It has no tests. The three batch files that installed and launched it (`install_windows.bat`, `start.bat`, `stop.bat`) were removed on 2026-10-05 because the installer changed system trust settings; they remain in the git history.

## Why it does not work

- `addon.py` posts to `/api/v1/dissonance/check`. The API serves `/v1/dissonance/check`, so the call gets 404.
- It sends the text in a field named `text`. The API requires `input_text` and answers 422.
- It reads a `decision` field that the API response does not contain.
- Blocking is hard-coded off (`BLOCK_ON_UNSAFE = False` in `addon.py`). The addon does not read `.env` or the environment, so setting `BLOCK_ON_UNSAFE=true` changes nothing.
- When the API returns an error or cannot be reached, the addon forwards the request anyway.
- The API key bundled in `addon.py` is 24 characters long. The API requires at least 32, so the addon could never authenticate.

## What the removed scripts did to a machine

This is what the batch files do when run, from reading them. They are no longer in this repository, but a copy the installer left on a machine still behaves this way.

`install_windows.bat`:

- clones the default branch of this repository to `%USERPROFILE%\EmberArmor`, or runs `git pull` there if it already exists
- runs `pip install` for this package and for mitmproxy with whichever `pip` is on the PATH; it does not create a virtual environment
- starts `mitmdump` briefly to generate a certificate authority, force-kills every running `mitmdump.exe`, then adds `%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer` to the machine-wide Windows Trusted Root store with `certutil -addstore`, asking for elevation if that fails
- asks for a Perplexity API key and writes it in plain text to `%USERPROFILE%\EmberArmor\.env`, replacing any file already there
- creates an "EmberArmor Proxy" shortcut on the Desktop

`start.bat`:

- runs `git pull` on every launch
- force-kills every process that has a `netstat` line matching port 8000, 8080 or 7070
- waits for the API in a loop with no timeout; if the API ever answered, it would set the per-user Windows proxy to `127.0.0.1:8080` and run `mitmdump` with no host filter, so everything that honours the system proxy would go through TLS interception, not only the AI hosts

`stop.bat` kills `mitmdump.exe` and the API window and switches the Windows proxy setting off.

Two of these mattered even though the proxy never got as far as running. The root certificate stays trusted after the installer exits, and mitmproxy keeps the private key that signs for it in `%USERPROFILE%\.mitmproxy`, where any program running as that user can read it. And because `start.bat` pulled the default branch on every launch, whatever was on that branch at that moment is what ran next. A copy of `start.bat` left on a machine by the installer still does this, so delete the installed folder (step 6 below).

## If you already ran the installer

1. Check for the certificate: `certutil -store Root mitmproxy` for the machine store and `certutil -user -store Root mitmproxy` for the current-user store. A store that does not hold it answers "Object was not found".
2. Remove it. In an administrator prompt run `certutil -delstore Root mitmproxy`, then do the same for the current-user store with `certutil -user -delstore Root mitmproxy`.
3. Delete `%USERPROFILE%\.mitmproxy`. mitmproxy keeps the private key for that certificate there.
4. Check that the Windows proxy setting is off: Settings, Network & internet, Proxy, "Use a proxy server".
5. Rotate any API key you pasted into the installer. It was saved in plain text in `%USERPROFILE%\EmberArmor\.env`.
6. Delete `%USERPROFILE%\EmberArmor` and the Desktop shortcut. The installer also added the `ember-armor` and `mitmproxy` packages to the Python on your PATH; uninstall them with `pip` if you do not use them.

## Files

| File | What it is |
|------|------------|
| `addon.py` | mitmproxy addon and a status page that is not started |
