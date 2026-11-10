# CyberGuard AI - Render deployment

Pure Python standard library. No pip packages are needed.

## 1. Put the project on GitHub
The GitHub repository root must be THIS folder's contents, so that `server.py` and `web/` are at the top level:

    server.py
    run.bat
    .python-version
    .gitignore
    DEPLOY-RENDER.md
    PROJECT-INFO.md
    IMPORTANT-NOTES.md
    render.yaml (optional)
    web/ (index.html, link.html, emoji.html, photo.html, deepfake.html, contacts.html, app.js, style.css, assets/)

Do NOT upload the `runtime/` folder. It holds Windows-only files (python.exe, .dll, .pyd) that Render (Linux) cannot use.
Keep it on your own PC: run.bat still needs it when Python is not installed there. `.gitignore` already excludes it.

## 2. Create the Render service
Render Dashboard -> New -> Web Service -> connect the GitHub repository.

| Setting            | Value                              |
|--------------------|------------------------------------|
| Language / Runtime | Python 3                           |
| Root Directory     | (leave empty)                      |
| Build Command      | `python -m py_compile server.py`   |
| Start Command      | `python server.py`                 |
| Health Check Path  | `/health`                          |

Python version is pinned to 3.12 by `.python-version` (Render's default for new services is newer; 3.12 is what this project was tested with).
Render sets `PORT` automatically; server.py then binds `0.0.0.0:$PORT`.

If your repository has an extra wrapper folder (for example `CyberGuard/server.py`), set Root Directory to that folder name instead.

## 3. Optional environment variables
| Name                   | Default (public) | Meaning                                  |
|------------------------|------------------|------------------------------------------|
| MAX_UPLOAD_MB          | 15               | Maximum image upload size                |
| RATE_LIMIT_PER_MIN     | 40               | Scans allowed per visitor IP per minute (0 = off) |
| MAX_CONCURRENT_SCANS   | 4                | Scans running at the same time           |
| CYBERGUARD_MODE        | auto             | `local` or `public` to force a mode      |

## 4. Modes
* Local (run.bat, no PORT set): 127.0.0.1, ports 8000-8010, opens the browser, no extra limits (30 MB uploads).
* Public (PORT set, i.e. Render): 0.0.0.0, exact PORT, no browser, SSRF-safe link scanning, 15 MB uploads, rate limiting, gzip, JSON errors without stack traces.

## 5. Public-mode link scanner
* Only public internet IP addresses on ports 80/443 are contacted. Private, loopback, link-local, metadata (169.254.169.254), multicast, reserved and IPv6-mapped/NAT64/6to4 addresses are refused.
* The server connects to the exact IP it validated (DNS-rebinding safe) and re-validates every redirect hop (max 5).
* Anything refused is reported in the result as "NOT PERFORMED on this public server" and is not counted in the score.
