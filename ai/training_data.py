"""
training_data.py - Labeled examples that TEACH the ML model.

Supervised learning = learning from examples where we already know the answer.
Each row is:   [impact, exploitability, confidence, data_exposure, user_interaction] -> label
Labels:        0 = Low, 1 = Medium, 2 = High, 3 = Critical

These seed examples encode security-expert judgement (similar to how CVSS and
the OWASP Top 10 rate real vulnerabilities). You can improve the model by
adding more rows - for example from real pentest reports you have studied.
"""
import random

LABELS = ["Low", "Medium", "High", "Critical"]

SEED_EXAMPLES = [
    # --- Critical: easy, no victim needed, big data/system impact -------------
    ([0.95, 0.90, 0.90, 1.00, 0.0], 3),  # error-based SQL injection
    ([0.95, 0.75, 0.70, 1.00, 0.0], 3),  # boolean SQL injection
    ([1.00, 0.90, 0.90, 1.00, 0.0], 3),  # remote code execution
    ([0.95, 0.95, 0.90, 0.95, 0.0], 3),  # exposed .git / .env with secrets
    ([0.90, 0.85, 0.80, 0.90, 0.0], 3),  # exposed database dump
    ([0.95, 0.80, 0.60, 0.90, 0.0], 3),  # unauthenticated admin API
    # --- High ---------------------------------------------------------------
    ([0.60, 0.80, 0.90, 0.40, 1.0], 2),  # reflected XSS
    ([0.70, 0.85, 0.90, 0.50, 1.0], 2),  # stored-ish XSS profile
    ([0.70, 0.50, 0.90, 0.50, 0.0], 2),  # risky service (redis/telnet) exposed
    ([0.75, 0.60, 0.60, 0.60, 0.0], 2),  # exposed DB port
    ([0.85, 0.95, 0.90, 0.85, 0.0], 2),  # config backup with credentials
    ([0.80, 0.50, 0.50, 0.80, 0.0], 2),  # unsure but serious injection
    ([0.60, 0.70, 0.70, 0.60, 1.0], 2),  # session theft scenario
    # --- Medium ---------------------------------------------------------------
    ([0.40, 0.90, 0.95, 0.50, 0.0], 1),  # directory listing
    ([0.50, 0.95, 0.90, 0.50, 0.0], 1),  # phpinfo page
    ([0.40, 0.35, 0.90, 0.30, 1.0], 1),  # cookie without HttpOnly
    ([0.30, 0.40, 0.80, 0.20, 0.0], 1),  # admin panel discovered
    ([0.70, 0.50, 0.60, 0.50, 0.0], 1),  # risky service, banner unclear
    ([0.40, 0.95, 0.90, 0.40, 0.0], 1),  # .DS_Store / file names leak
    ([0.55, 0.60, 0.40, 0.40, 1.0], 1),  # low-confidence XSS
    ([0.50, 0.50, 0.50, 0.50, 0.5], 1),  # generic middle case
    # --- Low ---------------------------------------------------------------
    ([0.25, 0.30, 1.00, 0.10, 1.0], 0),  # missing security header
    ([0.20, 0.40, 0.95, 0.20, 0.0], 0),  # server version disclosed
    ([0.10, 0.95, 0.90, 0.10, 0.0], 0),  # robots.txt
    ([0.30, 0.40, 0.60, 0.20, 0.0], 0),  # forbidden (403) admin path
    ([0.15, 0.20, 0.50, 0.10, 1.0], 0),  # weak referrer policy
    ([0.20, 0.30, 0.40, 0.10, 0.0], 0),  # uncertain informational item
    ([0.10, 0.10, 0.90, 0.05, 1.0], 0),  # missing permissions-policy
]


def build_training_set(copies: int = 12, noise: float = 0.05, seed: int = 42):
    """
    Data augmentation: make several slightly "wiggled" copies of each example
    so the model learns smooth boundaries instead of memorising 28 points.
    """
    rng = random.Random(seed)
    X, y = [], []
    for features, label in SEED_EXAMPLES:
        X.append(features)
        y.append(label)
        for _ in range(copies):
            X.append([min(1.0, max(0.0, f + rng.uniform(-noise, noise))) for f in features])
            y.append(label)
    return X, y
