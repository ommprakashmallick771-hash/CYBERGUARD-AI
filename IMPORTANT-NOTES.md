# CyberGuard AI - Important Notes (keep this file safe)

## A. Project at a glance
| Item | Value |
|------|-------|
| Entry file | `server.py` (run: `python server.py`) |
| Website files | `web/` (index, link, emoji, photo, deepfake, contacts + `app.js`, `style.css`, `assets/`) |
| Python | 3.12 (pinned in `.python-version`) - no pip packages |
| Health check | `/health` (returns status, mode, uptime, max upload) |
| Clean URLs | `/link`, `/emoji`, `/photo`, `/deepfake`, `/contacts` also work |

## B. Run on your PC (Windows)
Double-click `run.bat`. It uses installed Python or downloads a portable one, starts at `http://localhost:8000` and opens the browser. Keep the black window open.
Linux/Mac: `python3 server.py`.

## C. Deploy on Render (quick)
1. Upload the **contents** of this folder to a GitHub repo (`server.py` and `web/` at the top level). Do NOT upload `runtime/`.
2. Render -> New -> Web Service -> select repo.
3. Build Command `python -m py_compile server.py` | Start Command `python server.py` | Health Check Path `/health`.
4. Deploy. Details: `DEPLOY-RENDER.md`. After every `git push`, Render redeploys automatically.
Free plan note: the site sleeps after ~15 min of no visitors; the first visit then takes 30-60 s to wake up. This is normal.

## D. Environment variables (Render -> Environment)
| Name | Default | Use |
|------|---------|-----|
| `MAX_UPLOAD_MB` | 15 | Biggest photo allowed (phone photos are usually 2-8 MB) |
| `MAX_CONCURRENT_SCANS` | 4 | Scans at the same time (keep low on free plan) |
| `RATE_LIMIT_PER_MIN` | 40 | Scans per visitor per minute (0 = off) |
| `CYBERGUARD_MODE` | auto | `local` or `public` to force a mode |

## E. What was fixed for mobile (black screen)
- Images were 2-2.5 MB each (16 MB total). Now compressed WebP (~0.7 MB total) with lazy loading.
- The 3D globe did heavy maths every frame. Links are now pre-computed; phones use fewer points and 30 fps.
- Heavy GPU effects (blur, 3D transforms, will-change) are switched off on touch devices.
- Effects on phones/tablets: sparkle **only on tap**. Nothing follows the finger while moving or scrolling. Mouse trail + 3D tilt stay on PC only.
- Layout rules for phone (<560 px), small tablet (<820 px), tablet (<1024 px), laptop and TV (>1600 px); safe-area support for notched phones.

## F. Server features (server.py)
gzip compression, browser caching (images 7 days, code always re-checked with ETag), per-IP rate limit, SSRF-safe link scanning (private/metadata IPs blocked), size limits, no stack traces for visitors, security headers (HSTS, nosniff, Permissions-Policy), friendly 404 page, path-traversal protection, graceful shutdown on Render restarts.

## G. Troubleshooting
| Problem | Fix |
|---------|-----|
| Old design still shows on phone | Hard refresh / clear site data (old PNG/JS may be cached) |
| Render deploy fails "server.py not found" | Wrong Root Directory - files must be at repo top level, or set Root Directory to the wrapper folder |
| Blank page | Open `/health`; if it works, check the browser console. Make sure `web/assets/*.webp` was uploaded |
| "Too many scans" message | Rate limit hit; wait 1 minute or raise `RATE_LIMIT_PER_MIN` |
| Photo rejected as too large | Raise `MAX_UPLOAD_MB` (Render free plan has 512 MB RAM; do not go above ~25) |
| First load very slow | Free plan was sleeping - wait ~1 minute, or use an uptime pinger on `/health` |
| Link scan says "NOT PERFORMED" for a layer | Intentional: public server refuses private/internal addresses |

## H. Security rules (do not break)
- Never upload `runtime/`, passwords, tokens or `.env` files to GitHub.
- Do not remove the SSRF guard (`is_public_ip`, `fetch_safe`) - it stops people using your server to attack internal networks.
- Photos are scanned as **original bytes** on purpose (compressing would destroy hidden data), so there is no client-side image compression.
- Rate limit uses the visitor IP from `X-Forwarded-For`; it is a basic protection, not a firewall.

## I. Things to verify regularly
- Helpline numbers on the Contacts page (they can change) - check the official sites every few months.
- Keep Python version in `.python-version` in sync with what you tested.

## J. Credits and disclaimer
Created by **Omm Prakash Mallick**, SBD International School, Bhadrak. "CyberGuard" is an AI-powered tool and can make mistakes. For education and defensive awareness only; misuse is the user's sole responsibility.
