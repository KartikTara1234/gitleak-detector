# Demo video script (target: 3–4 minutes)

Record at 1080p with the browser at ~125% zoom so the findings are readable. Talk over it; no music needed.

## 0:00 – 0:25 · The problem
Screen: the landing page.
> "This is Repo Secret Sweeper. Developers commit API keys and .env files to GitHub constantly — tools exist to catch it, but they're CLI-only and nobody runs them. This is the web version: paste a repo, get an answer you can act on."

## 0:25 – 1:30 · The bad case
Click **scan the demo leaky repo**.
- Point at the **F / 0 score** and the severity counts.
- Scroll the findings. Call out three different *kinds*: a committed `.env` (filename rule), an AWS key in `src/config.js` (pattern rule), the `HMAC_SIGNING_KEY` in `src/auth.js` (entropy detector — "no known prefix, but it's random enough to be a secret").
- Point at `src/auth.js:2`: `changeme_please` is tagged **placeholder** and rated low. "The scanner knows the difference between a real key and a template."
- Click the **critical** chip off and on to show filtering.

## 1:30 – 2:15 · The fix
- Scroll to **Suggested .gitignore additions**, hit **Copy**.
- Scroll to the **Rotation checklist**. Open one provider (e.g. AWS), tick a step. Point at the docs link.
- Read the **Git history** item: "Deleting the file in a new commit doesn't remove it — the tool tells you that too."

## 2:15 – 3:00 · A real repo + false positives
- Paste `expressjs/express` → **A**, one medium finding (`.npmrc`). "A clean repo scores clean."
- Paste `motdotla/dotenv` → findings are all tagged **test / docs** and downgraded. "These are test fixtures. Same key in `src/` would be critical. Severity is contextual."
- Click a file:line link → it opens the exact line on GitHub at the scanned commit.

## 3:00 – 3:30 · Under the hood (optional, if time)
- Click **detection rules** in the header: 30 pattern rules, 9 file rules, entropy.
- Show the **Recent scans** sidebar; click an old one to reload it.
- One line on the stack: "React + Vite frontend, Express API, pure-Node scanner, MongoDB for history — optional, it falls back to memory."

## 3:30 · Close
> "Secrets are masked before they leave the scanner, clones are deleted after every run, and it deploys as one Docker image. Repo link and live URL are in the description."
