# Contributing to Ishtar

Thanks for wanting to help! Ishtar is an **educational, detection-only** scanner, and contributions
should keep it that way.

## Ground rules

- **Safety checks stay.** Do not remove or weaken the authorization prompt, the public-target lock,
  rate limiting, the crawl exclusions, or GET-only default testing. PRs that do will be closed.
- **Detection, not exploitation.** No data extraction, password brute-forcing, shells, or weaponized
  payloads. New checks must use harmless probes and confirm findings by evidence.
- **Only test on systems you own or are authorized to test**, such as the included
  `examples/demo_lab.py`, DVWA, or Juice Shop running locally.
- **Never commit scan reports, logs, cookies or API keys.** `reports/` is git-ignored for this reason.

## Getting started

1. Fork the repo and create a branch: `git checkout -b feature/my-check`
2. Set up the environment as described in the [README](README.md#installation-windows--macos--linux).
3. Start the demo lab with `python examples/demo_lab.py`, then scan it with
   `python main.py scan http://127.0.0.1:8099/ --ports 8099` to check that everything still works.

## Good first contributions

- New entries in `wordlists/common.txt`
- More labeled examples in `ai/training_data.py`, with a comment explaining each label
- Clearer beginner explanations in `ai/explainer.py`
- New detection-only checks in `scanner/`, each with a matching knowledge card in `ai/explainer.py`
  and a category profile in `ai/features.py`
- Translations of the docs (an Arabic guide already exists in `GUIDE_AR.md`)

## Code style

- Python 3.10+, standard library first, and keep dependencies small.
- Comment code for beginners: explain *why*, not only *what*.
- All network I/O goes through `scanner/http_client.py` so the rate limits apply everywhere.

## Pull requests

- Keep one topic per PR, and write a clear description of what changed and how you tested it.
- Include the command you ran against the demo lab and a short excerpt of the output.

## Reporting security issues

Please don't open public issues for vulnerabilities in Ishtar itself. See [SECURITY.md](SECURITY.md).
