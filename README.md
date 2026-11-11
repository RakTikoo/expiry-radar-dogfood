# expiry-radar-dogfood

Dogfood test repo for [Expiry Radar](https://github.com/RakTikoo/expiry-radar) **v0.2**.

It runs Expiry Radar's example weekly workflow (`.github/workflows/expiry-radar.yml`,
vendored `expiry_radar.py` — the pattern documented in the main repo) against two
deliberately planted artefacts:

- `tests/auth_tokens.py` — a JWT that is already **expired**
- `certs/api.pem` — a certificate **expiring within the 90-day window**

Expected behaviour: each workflow run keeps exactly ONE tracking issue titled
"⏰ Expiry Radar" (label `expiry-radar`) up to date — opened when findings appear,
edited in place on later runs, and commented + closed once the artefacts are fixed.
This repo exists purely to prove that lifecycle on real GitHub Actions; it is not
an application.
