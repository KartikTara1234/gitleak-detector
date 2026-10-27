# Repo Secret Sweeper

> Paste a public GitHub repository URL. Get back every leaked API key, token, password and committed `.env` file — with a hygiene score, a ready-to-paste `.gitignore` patch, and a provider-by-provider rotation checklist.

**Live demo:** _add your deployed URL here_  ·  **Demo video:** _add your video link here_

---

## Why this exists

Secrets get committed to git every day — a `.env` that was never ignored, an AWS key pasted into a config "just for now", a Slack webhook in a deploy script. Tools like `gitleaks` and `trufflehog` catch these, but they live on the command line and produce raw JSON. Most developers never run them.

Repo Secret Sweeper is the version a non-security developer will actually use: a web page where you paste a URL and get an answer you can act on in under a minute. It tells you **what** leaked, **where** (file + line, linked to GitHub), **how bad** it is, and **what to do about it** — rotate here, add this to `.gitignore`, rewrite history like this.

## What it does

| Workflow | Detail |
|---|---|
| **Scan a public repo** | Shallow-clones (`--depth 1`) into a temp directory, walks every text file, deletes the clone afterwards. Supports `owner/repo`, full URLs, and `/tree/<branch>`. |
| **Detect secrets** | 30 provider-specific pattern rules (AWS, GitHub, Stripe, Slack, OpenAI, MongoDB, private keys…), 9 sensitive-filename rules (`.env`, `*.pem`, `id_rsa`, service-account JSON…), and a Shannon-entropy detector for random-looking values assigned to credential-ish variable names. |
| **Cut false positives** | Placeholders (`your_key_here`, `${VAR}`, `process.env.X`, `localhost` URLs, vendor documentation examples) are downgraded to *low*. Findings inside `tests/`, `docs/`, fixtures and READMEs are downgraded one level and tagged. Generic matches that overlap a provider-specific match are dropped. |
| **Score it** | 0–100 hygiene score and an A–F grade. One real critical finding alone drops you to 75. |
| **Fix it** | Generated `.gitignore` additions, a provider-by-provider rotation checklist with console paths and docs links, and a Git-history section explaining why deleting the file in a new commit is not enough. |
| **Remember it** | Scan history (MongoDB, or in-memory if no URI is set). Findings are stored **masked only** — the raw secret is never persisted or returned. |

## Stack

- **Frontend:** React 18 + Vite, plain CSS (no component library).
- **Backend:** Node 18+ / Express. Scanner is pure Node (`fs`, `child_process`), no scanning library.
- **Database:** MongoDB via Mongoose, optional. Falls back to an in-memory ring buffer so the app runs with zero infrastructure.
- **Deploy:** Single Docker image — Express serves the built React app and the API from one port.

```
repo-secret-sweeper/
├── client/                 React app (Vite)
│   └── src/
│       ├── App.jsx         layout, state, API wiring
│       ├── api.js          fetch wrapper
│       └── components/     ScanForm, Report (score / findings / gitignore / rotation), History, Rules
├── server/
│   ├── src/
│   │   ├── index.js        Express routes, rate limiting, static serving
│   │   ├── github.js       URL parsing, shallow clone, cleanup
│   │   ├── scanner.js      file walk, pattern + entropy detection, scoring, gitignore + rotation builders
│   │   ├── rules.js        detection rules, placeholder hints, rotation steps per provider
│   │   └── store.js        MongoDB / in-memory scan history
│   └── test/               unit tests (node --test)
├── demo-leaky-repo.tar.gz  a deliberately insecure sample project, unpacked at startup — every secret is FAKE
├── Dockerfile · render.yaml · .env.example
```

## Run locally

Requires Node 18+ and `git` on your PATH.

```bash
git clone https://github.com/KartikTara1234/gitleak-detector.git
cd gitleak-detector
npm install              # installs `concurrently` at the root
npm run install:all      # installs server + client deps
cp .env.example server/.env   # optional: set MONGODB_URI for persistent history
npm run dev              # API on :4000, React on :5173 (proxies /api)
```

Open http://localhost:5173, click **scan the demo leaky repo**, then try a real one, e.g. `expressjs/express` (clean) or `motdotla/dotenv` (test fixtures that look like secrets — a good false-positive demo).

Run the tests:

```bash
npm test
```

### Production build

```bash
npm run build            # builds client/dist
npm start                # Express serves client/dist + /api on :4000
```

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | `{ ok, store: "memory" \| "mongodb", rules }` |
| `GET` | `/api/rules` | Pattern and filename rules the scanner uses |
| `POST` | `/api/scan` | Body `{ repoUrl }` or `{ demo: true }`. Returns the full report. |
| `GET` | `/api/scans` | Recent scans (summary only) |
| `GET` | `/api/scans/:id` | Full report for one scan |

Rate limited to 6 scans per IP per minute (`SCANS_PER_MINUTE`) and one concurrent scan per IP. Clones time out after 90 s; files over 1 MB, binaries, lockfiles and `node_modules`/`dist`/`.git` are skipped.

## Deploy

**Render (free tier, recommended):** New → Blueprint → select this repo. `render.yaml` builds the Dockerfile. Set `MONGODB_URI` in the dashboard if you want persistent history (MongoDB Atlas free tier works).

**Any Docker host:**

```bash
docker build -t sweeper .
docker run -p 4000:4000 -e MONGODB_URI="..." sweeper
```

**Railway / Fly.io:** both detect the Dockerfile automatically.

## Engineering decisions

- **Shallow clone instead of the GitHub API.** The contents API is rate-limited to 60 requests/hour unauthenticated and needs one call per file. `git clone --depth 1` fetches a whole repo in one round trip and needs no token.
- **Pattern rules over a general regex.** A rule that fires on every 32-char hex string is worse than no rule. Each rule targets a provider's real token format; a generic "assignment of something secret-ish" rule and an entropy detector cover the rest at lower severity.
- **Severity is contextual.** The same key is *critical* in `src/config.js`, *high* in `tests/fixtures.js`, and *low* if it's `AKIAIOSFODNN7EXAMPLE` from the AWS docs. Dumping everything as "critical" trains people to ignore the tool.
- **Mask at the source.** The scanner masks before anything leaves `scanDirectory()`, so the API, the database and the UI never see a raw secret. A secret scanner that stores secrets would be its own leak.
- **MongoDB optional.** History persists when a URI is set, otherwise it lives in memory. The app should work on a free host with no database — the scan is the product, history is a convenience.
- **Clones are temp and deleted in `finally`.** Even if a scan throws, the checkout is removed.
- **The model never sees a secret.** Context lines and snippets are masked at scan time (file-wide, so a key on the neighbouring line is masked too) before they are stored or sent anywhere.

## Limitations & next steps

- Scans the latest commit on one branch only. Secrets removed in a later commit but still in history are not found — history scanning (`git log -p`) is the obvious next step.
- Public repositories only. Private repos would need a GitHub OAuth app or a user-supplied token.
- Pattern rules are hand-maintained; new providers need a new entry in `rules.js`.
- No verification that a found key is still live. (Deliberate — hitting a provider with someone else's key is not something a demo app should do.)

## The demo repo

`demo-leaky-repo.tar.gz` (unpacked to `demo-leaky-repo/` when the server starts) is a sample project seeded with 20+ fake credentials in all the usual places: a committed `.env`, hardcoded AWS/GitHub/Google keys, connection strings with passwords, a Slack webhook, a private key file, a service-account JSON, and a few deliberate placeholders so the downgrade logic is visible. **None of the values are real.** It ships compressed because GitHub's push protection would (correctly!) refuse a commit containing them as plain files — which is itself a nice demonstration of why this tool exists.
