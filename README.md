# AI Recon Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Purpose](https://img.shields.io/badge/purpose-education%20%2F%20authorized%20testing-orange)

An educational, AI-assisted reconnaissance and web-vulnerability scanner written in Python.
It scans a target **you are authorized to test**, detects common weaknesses, and uses a
machine-learning model to rank every finding by severity and explain it in plain language.

> 🇮🇶 Arabic step-by-step guide: [GUIDE_AR.md](GUIDE_AR.md)

---

## ⚠️ ETHICS - read this first

- **Only scan systems you own, or legal practice labs**: DVWA, Metasploitable, OWASP Juice Shop
  on your own machine, or the official labs of **TryHackMe** and **HackTheBox** while connected to their VPN.
- **Scanning systems without permission is illegal** in almost every country (e.g. the US CFAA,
  the UK Computer Misuse Act, and similar cybercrime laws elsewhere), even if you "only look".
- A bug-bounty program only authorizes what is listed **in its scope**. Read the rules first.
- This tool is **detection-only**: it does not exploit vulnerabilities, extract data, or
  brute-force passwords. Keep it that way.

Safety features built into the tool:

| Protection | What it does |
|---|---|
| Authorization prompt | Every scan asks you to confirm you own or are authorized to test the target. |
| Target classification | `localhost`, private LAN IPs and the `ALLOW_LIST` in `config.py` are accepted after confirmation. |
| Public-target lock | Public IPs/domains require typing `I am authorized to test <host>` exactly. `--yes` cannot skip this. |
| Rate limiting | Max 15 HTTP requests/second and 5 in parallel by default (`--rate` to lower). |
| Safe crawling | URLs with `logout`, `setup`, `reset`, `csrf`, `password`… are never touched (so you can't break your lab). |
| GET-only by default | POST forms are tested only with `--test-post`. |
| Harmless probes | XSS uses a random fake tag (`"><zx1a2b3c>`), never `<script>`. SQLi uses `'` and TRUE/FALSE comparisons only. |

---

## Features

1. **Recon**: async TCP port scan (common ports or the full 1-65535 range), banner and version
   detection, and directory enumeration with a wordlist (with soft-404 detection).
2. **Web checks (detection only)**: reflected XSS, SQL injection (error-based and boolean-based),
   missing security headers, insecure cookies, version disclosure, exposed sensitive files
   (`.git`, `.env`, backups, phpinfo…), and directory listing.
3. **AI layer**: a Random-Forest + rule hybrid ranks findings as Critical/High/Medium/Low, adds a plain-language
   explanation, why it matters, and a suggested fix. If `ANTHROPIC_API_KEY` is set,
   Claude writes the executive summary; otherwise everything runs offline.
4. **Reporting**: a Flask dashboard with color-coded severities and charts, plus HTML and JSON export.

## Project structure

```
ai-recon-scanner/
├── main.py               # command-line entry point (scan / dashboard)
├── config.py             # all settings (timeouts, rate limits, allow-list)
├── safety.py             # authorization gate
├── recon/
│   ├── port_scanner.py   # async port scan + banner grabbing
│   └── dir_enum.py       # directory enumeration
├── scanner/
│   ├── http_client.py    # rate-limited async HTTP client
│   ├── crawler.py        # finds links, forms, parameters
│   ├── xss.py            # reflected XSS detection
│   ├── sqli.py           # SQL injection detection
│   └── headers.py        # headers, cookies, sensitive files
├── ai/
│   ├── features.py       # finding -> numeric feature vector
│   ├── training_data.py  # labeled examples the model learns from
│   ├── prioritizer.py    # Random Forest + rule scoring
│   ├── explainer.py      # plain-language explanations + next steps
│   └── llm.py            # optional Claude summary
├── app/
│   ├── server.py         # Flask dashboard
│   ├── report_export.py  # HTML / JSON export
│   └── templates/
├── wordlists/common.txt
├── reports/              # your scan results are saved here
└── requirements.txt
```

---

## Installation (Windows / macOS / Linux)

You need **Python 3.10+**.

```bash
git clone https://github.com/jm3ax0/ai-recon-scanner.git
```

```bash
cd ai-recon-scanner
```

```bash
python -m venv .venv
```

Activate the virtual environment. On Windows (PowerShell):

```bash
.\.venv\Scripts\Activate.ps1
```

On macOS / Linux:

```bash
source .venv/bin/activate
```

Then install the requirements:

```bash
pip install -r requirements.txt
```

## Usage

Quick scan of your own machine:

```bash
python main.py scan 127.0.0.1
```

Scan a web app (DVWA example, see the lab section below):

```bash
python main.py scan http://127.0.0.1:8080/ --cookie "PHPSESSID=YOUR_ID; security=low"
```

Full port range, no web checks:

```bash
python main.py scan 192.168.1.20 --ports full --no-web
```

Open the dashboard at http://127.0.0.1:5050:

```bash
python main.py dashboard
```

| Option | Meaning |
|---|---|
| `--ports common\|full\|1-1024,8080` | Which TCP ports to scan |
| `--cookie "..."` | Send a session cookie (needed for apps behind a login, like DVWA) |
| `--wordlist path` | Custom wordlist for directory enumeration |
| `--rate N` | Max HTTP requests per second (default 15) |
| `--test-post` | Also test POST forms (off by default because it can change lab data) |
| `--no-web` | Port scan only |
| `--no-llm` | Never call the LLM API |
| `--lang ar` | LLM summary in Arabic |
| `--yes` | Skip the confirm prompt for local/private targets |
| `-v` | Verbose logging (also written to `reports/scanner.log`) |

### Optional: LLM summaries with Claude

```bash
setx ANTHROPIC_API_KEY "sk-ant-..."
```

On macOS/Linux use `export ANTHROPIC_API_KEY=sk-ant-...` instead. Open a new terminal afterwards.
When the key is set, a compact list of findings (titles, URLs, evidence) is sent to the Anthropic API
to write the summary. The tool uses model `claude-opus-5-5` with server-side fallback enabled, so if the
model declines a request the API retries on a suitable model. Without a key, or with `--no-llm`,
nothing leaves your machine.

---

## Practice lab: DVWA with Docker (100% legal, on your own PC)

1. Install **Docker Desktop**: https://www.docker.com/products/docker-desktop/ (on Windows, enable WSL 2 when asked), then start it.
2. Start DVWA. It's bound to `127.0.0.1` only, so nobody on your network can reach this vulnerable app:
   ```bash
   docker run -d --name dvwa -p 127.0.0.1:8080:80 vulnerables/web-dvwa
   ```
3. Open http://127.0.0.1:8080/setup.php and click **Create / Reset Database**.
4. Log in at http://127.0.0.1:8080/login.php with `admin` / `password`.
5. Open **DVWA Security** (left menu), set the level to **Low**, and click Submit.
6. Copy your session cookie: press **F12**, then go to **Application** (Chrome) or **Storage** (Firefox),
   then **Cookies**, then `http://127.0.0.1:8080`. Copy the value of `PHPSESSID`.
7. Scan:
   ```bash
   python main.py scan http://127.0.0.1:8080/ --cookie "PHPSESSID=PASTE_HERE; security=low"
   ```
   Expected results: SQL injection in `/vulnerabilities/sqli/` (`id`), reflected XSS in
   `/vulnerabilities/xss_r/` (`name`), missing headers, cookie flags, and version disclosure.
8. Try `security=medium` and `high` and compare how the findings change. That's how you learn what each defense does.
9. When you're finished, run `docker stop dvwa`. Start it again later with `docker start dvwa`.

> If the scan reports "Redirected to a login page", your cookie expired. Log in again and copy a fresh `PHPSESSID`.

Other legal targets: `docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop` (OWASP Juice Shop),
Metasploitable 2 as a VirtualBox VM on a **host-only** network, and TryHackMe / HackTheBox machines
(add their VPN IP to `ALLOW_LIST` in `config.py`).

---

## How the AI prioritizes vulnerabilities (plain words)

A scanner can produce dozens of findings, and a beginner doesn't know which to fix first. The AI layer
acts like a junior security analyst that sorts them.

1. **Describe each finding with numbers.** Every finding becomes 5 values between 0 and 1:
   *impact* (how much damage), *exploitability* (how easy), *confidence* (how sure the scanner is),
   *data exposure* (can it leak data), and *user interaction* (does a victim need to click). These ideas come
   from CVSS, the industry standard for rating vulnerabilities.
2. **Learn from labeled examples.** A **Random Forest** (100 small decision trees that vote) is trained on
   examples that experts have already rated, such as "SQL injection = Critical" or "missing header = Low".
   Slightly varied copies of each example (data augmentation) help it learn smooth decision boundaries.
3. **Check it with transparent rules.** A simple weighted formula, which a human can verify by hand,
   gives a second score.
4. **Combine both.** `final = 0.6 × ML score + 0.4 × rule score` (0-10), then map the score to
   Critical, High, Medium or Low. The ML part captures patterns from examples; the rule part keeps
   results explainable and stable.
5. **Explain.** Each finding gets reasons (e.g. "easy to exploit, no victim interaction needed"),
   a plain-language description, and a next step. Optionally, an LLM (Claude) writes a summary.

**Sentence you can use in a motivation letter:**
> "I built an AI-assisted vulnerability scanner in Python that converts raw security findings into
> CVSS-inspired feature vectors and ranks them with a hybrid of a Random-Forest classifier and a
> transparent rule-based score, generating plain-language explanations and remediation steps, with an
> optional large-language-model summary. This taught me how machine learning can support human decision-making
> in cybersecurity while staying explainable."

## Limitations (be honest about them)

- The training set is small and hand-labeled, so the model reflects the author's judgement, not real-world statistics.
- The tool only checks for reflected XSS and basic SQL injection; stored or DOM XSS, blind time-based SQLi,
  authentication flaws and similar issues are not covered.
- Every finding must be verified manually. Automated scanners produce both false positives and false negatives.

## License

MIT, see [LICENSE](LICENSE). Use it only for education and on systems you are authorized to test.
