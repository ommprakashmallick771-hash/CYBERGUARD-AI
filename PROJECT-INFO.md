# CyberGuard AI - Project Information

**Created by:** Omm Prakash Mallick, SBD International School, Bhadrak (Odisha, India)
**Type:** Web application - cyber-safety toolkit (education and defensive awareness)
**Tech:** Python 3.12 standard library only (no pip packages) + plain HTML / CSS / JavaScript

## 1. What is CyberGuard AI?
CyberGuard AI is a free website that helps ordinary people - students, parents, teachers - check whether a link, an emoji/text message or a photo is dangerous **before** they trust it. Every scan runs through 8 independent analysis layers and ends with a risk score, a plain-language verdict, an explanation and a downloadable report.

## 2. Problem statement
- Millions of people receive links, messages and pictures every day that look harmless but hide phishing traps, invisible commands or fake AI-made content.
- Most people cannot judge this by eye. Existing tools are English-only, technical, paid, or only check a blacklist.
- Students and families are the most targeted group (fake prize links, fake KYC/UPI messages, deepfake photos, hidden code in files), and they often do not know whom to call after being cheated.

## 3. Our solution (4 scanners + 1 help page)
| Tool | What it finds |
|------|---------------|
| Phishing Link Detector | Fake/brand-copy domains, bad TLDs, DNS, TLS certificate, redirects, password forms, domain age, ML risk score |
| Emoji & Text Hidden-Code Scanner | Zero-width characters, Unicode TAG characters, variation selectors, bidi tricks, crash/zalgo text, scripts, Base64 payloads - and decodes hidden secret text |
| Photo Hidden-Code Scanner | Real file type, bytes after image end, metadata, embedded archives/executables, script patterns, LSB steganography |
| DeepFake & AI-Image Scanner | AI generator signatures, C2PA provenance, missing camera EXIF, diffusion image sizes, editing traces, pixel noise, colour statistics |
| Important Contacts | 20 official helplines (India + international): Cyber Crime 1930, CERT-In, RBI, NPCI, TRAI, SEBI, UIDAI and more |

## 4. How it helps in the future
1. **Prevents fraud** - a person who scans first does not lose money or passwords.
2. **Cyber-awareness at school level** - can be used in classrooms and cyber-safety weeks as a live demo.
3. **Faster reporting** - the contacts page tells victims exactly where to report (1930, cybercrime.gov.in).
4. **Teaches how attacks work** - every layer explains *why* something is risky, so users learn.
5. **Privacy friendly** - uploaded images and text are analysed in memory and are not stored.
6. **Easy to extend** - pure-Python, one server file; new layers and languages can be added quickly.

## 5. Future scope
- Hindi and Odia language interface
- QR-code scanner (quishing) and APK/PDF scanner
- Browser extension and WhatsApp-share integration
- Larger trained ML model, community-reported scam database
- Installable PWA (works like an app on phones)

## 6. How it works (architecture)
Browser (HTML/CSS/JS pages) -> `POST /api/link | /api/emoji | /api/photo | /api/deepfake` -> `server.py` runs the 8 layers -> JSON result (score, verdict, layers, tables, report) -> browser shows cards and a downloadable `.txt` report.

## 7. Limitations (honest disclosure)
CyberGuard is AI-assisted and **can make mistakes**. Results are guidance, not legal or court-grade proof. Always confirm with the official agencies listed on the Contacts page.

## 8. Disclaimer
Built for education and defensive security awareness only. Any illegal use is the sole responsibility of the user; the creator and the school are not liable for misuse.
