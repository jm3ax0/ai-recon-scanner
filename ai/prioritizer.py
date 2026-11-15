"""
prioritizer.py - The AI brain that ranks findings by severity.

It combines TWO opinions (a "hybrid" model):

  1. ML opinion  - a Random Forest classifier (100 small decision trees that
                   vote) trained on labeled examples. It outputs a probability
                   for each class: Low / Medium / High / Critical.
  2. Rule opinion - a transparent weighted formula (like CVSS) that a human
                   can check by hand.

  final_score (0-10) = 0.6 * ML expected score + 0.4 * rule score

Why both? The ML part learns non-obvious combinations from examples; the rule
part keeps the result explainable and stable. Then:
  score >= 8.5 -> Critical,  >= 6.5 -> High,  >= 3.5 -> Medium,  else Low
"""
import logging

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from ai.features import FEATURE_NAMES, extract_features
from ai.training_data import LABELS, build_training_set

log = logging.getLogger(__name__)

# The "typical" 0-10 score for each class, used to turn probabilities into a number.
CLASS_SCORES = np.array([2.0, 5.5, 8.0, 9.5])   # Low, Medium, High, Critical
ML_WEIGHT, RULE_WEIGHT = 0.6, 0.4
RULE_WEIGHTS = {"impact": 0.45, "exploitability": 0.25, "data_exposure": 0.20, "no_user_interaction": 0.10}


def severity_from_score(score: float) -> str:
    if score >= 8.5:
        return "Critical"
    if score >= 6.5:
        return "High"
    if score >= 3.5:
        return "Medium"
    return "Low"


def rule_score(f: dict) -> float:
    """Transparent formula. Low confidence pulls the score down (by up to half)."""
    base = (RULE_WEIGHTS["impact"] * f["impact"]
            + RULE_WEIGHTS["exploitability"] * f["exploitability"]
            + RULE_WEIGHTS["data_exposure"] * f["data_exposure"]
            + RULE_WEIGHTS["no_user_interaction"] * (1 - f["user_interaction"]))
    return 10 * base * (0.5 + 0.5 * f["confidence"])


def reasons_for(f: dict) -> list[str]:
    """Human-readable reasons behind the score."""
    r = []
    if f["impact"] >= 0.8:
        r.append("very high impact if exploited")
    elif f["impact"] >= 0.5:
        r.append("moderate impact if exploited")
    if f["exploitability"] >= 0.8:
        r.append("easy to exploit")
    if f["data_exposure"] >= 0.8:
        r.append("can expose sensitive data")
    if f["user_interaction"] >= 0.5:
        r.append("needs a victim to interact (lowers risk)")
    else:
        r.append("no victim interaction needed")
    if f["confidence"] < 0.7:
        r.append("scanner is not fully certain - verify manually")
    return r


class Prioritizer:
    def __init__(self):
        X, y = build_training_set()
        self.model = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
        self.model.fit(np.array(X), np.array(y))
        log.info("Severity model trained on %d examples", len(X))

    def feature_importances(self) -> dict:
        """Which features the trained forest relies on most (sums to 1.0)."""
        return {name: round(float(v), 3)
                for name, v in zip(FEATURE_NAMES, self.model.feature_importances_)}

    def score(self, findings: list[dict]) -> list[dict]:
        """Add severity/score/ML details to every finding and sort worst-first."""
        if not findings:
            return []
        X = np.array([extract_features(f) for f in findings])
        probas = self.model.predict_proba(X)
        # predict_proba columns follow model.classes_ (0..3); map them to the 4 labels
        full = np.zeros((len(findings), 4))
        full[:, self.model.classes_] = probas

        for finding, vec, p in zip(findings, X, full):
            feats = dict(zip(FEATURE_NAMES, vec.tolist()))
            ml_score = float(p @ CLASS_SCORES)
            r_score = rule_score(feats)
            final = round(ML_WEIGHT * ml_score + RULE_WEIGHT * r_score, 2)
            finding.update({
                "features": feats,
                "ml_probabilities": {LABELS[i]: round(float(p[i]), 3) for i in range(4)},
                "ml_prediction": LABELS[int(np.argmax(p))],
                "ml_score": round(ml_score, 2),
                "rule_score": round(r_score, 2),
                "score": final,
                "severity": severity_from_score(final),
                "reasons": reasons_for(feats),
            })
        findings.sort(key=lambda f: f["score"], reverse=True)
        for i, f in enumerate(findings, 1):
            f["id"] = i
            f["priority"] = i
        return findings
