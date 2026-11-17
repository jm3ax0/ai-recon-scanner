# Security Policy

## Reporting a vulnerability in Ishtar

If you find a security problem **in Ishtar itself**, please report it privately so it can be fixed
before details are public. Examples include a way to bypass the authorization prompt, the
dashboard leaking reports, or the HTML report being injectable.

1. Go to the repository's **Security** tab, then **Report a vulnerability** (GitHub private vulnerability reporting).
2. Include:
   - what the problem is and why it matters
   - steps to reproduce, using only your own machine or the included `examples/demo_lab.py`
   - the Ishtar version (see `TOOL_VERSION` in `config.py`) and your OS/Python version
   - a suggested fix, if you have one
3. Please **do not** open a public issue or PR that describes the vulnerability until it is fixed.

This is a student project maintained in spare time. You can expect an acknowledgement within about
7 days and an update once a fix is planned. Reporters are credited in the fix commit unless they
prefer otherwise.

## What is NOT a vulnerability here

- `examples/demo_lab.py` is **intentionally vulnerable**. That's its purpose, and it only listens on `127.0.0.1`.
- Findings Ishtar reports about **other** software (DVWA, your own apps) belong to the owners of that
  software, not this repository.

## Responsible use

Ishtar is for education and **authorized testing only**. Never use it, or proofs of concept for issues
in it, against systems you don't own or have written permission to test.

## Supported versions

Only the latest version on the `main` branch receives fixes.
