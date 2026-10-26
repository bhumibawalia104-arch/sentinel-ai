"""
Layer 3: Risk decision engine.

Combines the rule score (0-100) and ML score (0-100) into one risk score,
applies thresholds and writes a readable explanation.

IMPORTANT: the risk score is a heuristic ranking, NOT a calibrated probability.
"""
from app import config
from app.detection import ml_classifier, rules
from app.detection.normalizer import normalize

DISCLAIMER = ("Risk score is a heuristic (0-100), not a calibrated probability. "
              "No filter stops every prompt injection attack.")


def _verdict(score: int) -> str:
    if score >= config.BLOCK_THRESHOLD:
        return "BLOCKED"
    if score >= config.SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"
    return "ALLOWED"


def _category(matches, ml, score) -> str:
    if score < config.SUSPICIOUS_THRESHOLD:
        return "benign"
    # If a trick was used to hide the instruction, the category is "encoded/obfuscated"
    if any(m["rule_id"] == "hidden_payload" for m in matches):
        return "encoded_obfuscation"
    if matches:
        totals = {}
        for m in matches:
            totals[m["category"]] = 1 - (1 - totals.get(m["category"], 0)) * (1 - m["weight"])
        return max(totals, key=totals.get)
    return ml["top_category"] if ml["available"] and ml["p_malicious"] >= 0.5 else "benign"


def _confidence(rule_score: float, ml_score, score: int):
    """Show uncertainty: do the two layers agree?"""
    if ml_score is None:
        return "medium", "ML layer is unavailable, so this result uses rules only."
    both_high = rule_score >= 50 and ml_score >= 50
    both_low = rule_score < 25 and ml_score < 35
    disagree = (rule_score >= 50 and ml_score < 25) or (ml_score >= 50 and rule_score < 25)
    if both_high or both_low:
        return "high", None
    if disagree:
        return "low", ("The rule engine and the ML model disagree "
                       f"(rules {rule_score:.0f}, ML {ml_score:.0f}). Treat this verdict as uncertain.")
    if config.SUSPICIOUS_THRESHOLD <= score < config.BLOCK_THRESHOLD:
        return "medium", "Borderline result: this prompt may be legitimate. Human review is recommended."
    return "medium", None


def _explain(verdict, score, category_label, matches, rule_score, ml, ml_score, notes) -> str:
    parts = [f"{verdict} with risk {score}/100."]
    if matches:
        top = sorted(matches, key=lambda m: -m["weight"])[:3]
        parts.append("Rule engine (%.0f/100) matched: %s." % (rule_score, "; ".join(m["description"].lower() for m in top)))
    else:
        parts.append("Rule engine (0/100) found no known attack pattern.")
    if ml["available"]:
        parts.append(f"ML model suspicion score {ml_score:.0f}/100 (closest attack type: "
                     f"{rules.CATEGORY_LABELS[ml['top_category']].lower()}).")
    if notes:
        parts.append("Obfuscation handling: " + "; ".join(notes[:2]) + ".")
    if verdict != "ALLOWED":
        parts.append(f"Detected category: {category_label}.")
    return " ".join(parts)


def analyze(prompt: str) -> dict:
    norm = normalize(prompt)
    matches = rules.scan(norm)
    r_score = rules.rule_score(matches)

    ml = ml_classifier.predict(norm["ml_text"])
    m_score = round(ml["p_malicious"] * 100, 1) if ml["available"] else None

    if m_score is None:
        blended = r_score
    else:
        blended = config.RULE_WEIGHT * r_score + config.ML_WEIGHT * m_score
        blended = max(blended, config.RULE_FLOOR_FACTOR * r_score)   # strong rule evidence is never diluted
    score = int(round(min(blended, 100)))

    verdict = _verdict(score)
    category = _category(matches, ml, score)
    confidence, note = _confidence(r_score, m_score, score)
    label = rules.CATEGORY_LABELS[category]

    ml_top = sorted(({"label": rules.CATEGORY_LABELS[k], "probability": round(v, 3)}
                     for k, v in ml["probabilities"].items()), key=lambda d: -d["probability"])[:3]

    return {
        "risk_score": score, "verdict": verdict, "category": category, "category_label": label,
        "rule_score": r_score, "ml_score": m_score, "ml_available": ml["available"],
        "confidence": confidence, "uncertainty_note": note,
        "matched_rules": sorted(matches, key=lambda m: -m["weight"]),
        "normalization_notes": norm["notes"], "ml_top": ml_top,
        "explanation": _explain(verdict, score, label, matches, r_score, ml, m_score, norm["notes"]),
        "thresholds": {"suspicious": config.SUSPICIOUS_THRESHOLD, "blocked": config.BLOCK_THRESHOLD},
        "disclaimer": DISCLAIMER,
    }
