"""
features.py - Turn a security finding into NUMBERS a machine-learning model understands.

ML models cannot read text like "Reflected XSS in parameter q". They need a
list of numbers called a FEATURE VECTOR. We describe every finding with 5
features, each between 0.0 and 1.0 (inspired by the industry CVSS standard):

  impact           How much damage if an attacker uses it?   (1.0 = full takeover)
  exploitability   How easy is it to use?                    (1.0 = trivial)
  confidence       How sure is the scanner it's real?        (1.0 = certain)
  data_exposure    Can it leak or steal data?                (1.0 = whole database)
  user_interaction Does a victim have to click something?    (1.0 = yes, needs a victim)
"""

FEATURE_NAMES = ["impact", "exploitability", "confidence", "data_exposure", "user_interaction"]

# Expert knowledge: the "typical" profile of each category of finding.
CATEGORY_PROFILE = {
    "sqli_error":       {"impact": 0.95, "exploitability": 0.90, "data_exposure": 1.00, "user_interaction": 0.0},
    "sqli_boolean":     {"impact": 0.95, "exploitability": 0.75, "data_exposure": 1.00, "user_interaction": 0.0},
    "xss":              {"impact": 0.60, "exploitability": 0.80, "data_exposure": 0.40, "user_interaction": 1.0},
    "sensitive_file":   {"impact": 0.80, "exploitability": 0.95, "data_exposure": 0.90, "user_interaction": 0.0},
    "dir_listing":      {"impact": 0.40, "exploitability": 0.90, "data_exposure": 0.50, "user_interaction": 0.0},
    "risky_service":    {"impact": 0.70, "exploitability": 0.50, "data_exposure": 0.50, "user_interaction": 0.0},
    "interesting_path": {"impact": 0.30, "exploitability": 0.40, "data_exposure": 0.20, "user_interaction": 0.0},
    "insecure_cookie":  {"impact": 0.40, "exploitability": 0.35, "data_exposure": 0.30, "user_interaction": 1.0},
    "missing_header":   {"impact": 0.25, "exploitability": 0.30, "data_exposure": 0.10, "user_interaction": 1.0},
    "info_disclosure":  {"impact": 0.20, "exploitability": 0.40, "data_exposure": 0.20, "user_interaction": 0.0},
}
DEFAULT_PROFILE = {"impact": 0.3, "exploitability": 0.3, "data_exposure": 0.2, "user_interaction": 0.5}


def extract_features(finding: dict) -> list[float]:
    """finding (dict) -> [impact, exploitability, confidence, data_exposure, user_interaction]"""
    profile = dict(CATEGORY_PROFILE.get(finding.get("category"), DEFAULT_PROFILE))
    profile["confidence"] = float(finding.get("confidence", 0.5))
    # A scanner module can adjust the profile for one specific finding
    # (e.g. an exposed .git folder is much worse than robots.txt).
    profile.update(finding.get("overrides", {}))
    return [round(float(profile[name]), 3) for name in FEATURE_NAMES]
