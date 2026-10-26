"""
Layer 0: Normalizer.

Attackers hide instructions with tricks (base64, leetspeak, spaced letters...).
This module produces several "views" of the prompt so the rule engine and the
ML model can look at the revealed text too.
"""
import base64
import binascii
import codecs
import re
import unicodedata

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
LEET_MAP = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
SPACED_RE = re.compile(r"(?<![A-Za-z])(?:[A-Za-z] ){3,}[A-Za-z](?![A-Za-z])")        # i g n o r e
DASHED_RE = re.compile(r"(?<![A-Za-z])(?:[A-Za-z][-_.]){3,}[A-Za-z](?![A-Za-z])")     # i-g-n-o-r-e
CONCAT_RE = re.compile(r"""['"]\s*\+\s*['"]""")                                      # 'ig' + 'nore'
LEET_WORD_RE = re.compile(r"[a-z][013457@$][a-z]")


def _looks_like_text(text: str) -> bool:
    """Decoded bytes only count if they look like a real sentence."""
    if len(text) < 8 or " " not in text:
        return False
    printable = sum(ch.isprintable() for ch in text)
    return printable / len(text) >= 0.95


def _try_base64(token: str):
    token = token.rstrip("=")
    try:
        raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if _looks_like_text(text) else None


def _try_hex(token: str):
    try:
        text = bytes.fromhex(token).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
    return text if _looks_like_text(text) else None


def normalize(prompt: str) -> dict:
    """
    Returns:
      variants : list of (source, text). source is "original", "decoded" or "deobfuscated"
      notes    : human-readable notes about what was found
      ml_text  : single string given to the ML model
    """
    notes = []
    text = unicodedata.normalize("NFKC", prompt)          # full-width letters -> normal letters
    if text != prompt:
        notes.append("Unicode look-alike characters were converted to plain letters")

    cleaned = text.translate(ZERO_WIDTH)
    if cleaned != text:
        notes.append("Hidden zero-width characters were removed")
    text = cleaned
    lower = text.lower()

    variants = [("original", lower)]
    extras = []   # texts revealed by decoding / deobfuscation

    # --- decoded payloads -------------------------------------------------
    for token in B64_RE.findall(text):
        decoded = _try_base64(token)
        if decoded:
            notes.append("Base64 text decoded to: \"%s\"" % decoded[:60])
            variants.append(("decoded", decoded.lower()))
            extras.append(decoded.lower())
    for token in HEX_RE.findall(text):
        decoded = _try_hex(token)
        if decoded:
            notes.append("Hex text decoded to: \"%s\"" % decoded[:60])
            variants.append(("decoded", decoded.lower()))
            extras.append(decoded.lower())
    if re.search(r"rot-?13", lower):
        rot = codecs.decode(lower, "rot13")
        notes.append("ROT13 mentioned: checked the decoded version too")
        variants.append(("decoded", rot))
        extras.append(rot)
    if "revers" in lower:
        rev = lower[::-1]
        notes.append("Reversed text mentioned: checked the reversed version too")
        variants.append(("decoded", rev))
        extras.append(rev)

    # --- de-obfuscation ---------------------------------------------------
    collapsed = lower
    for pattern in (SPACED_RE, DASHED_RE):
        collapsed = pattern.sub(lambda m: re.sub(r"[-_. ]", "", m.group()), collapsed)
    if CONCAT_RE.search(collapsed):
        collapsed = CONCAT_RE.sub("", collapsed)
    if collapsed != lower:
        notes.append("Spaced-out or split-up letters were joined back together")
        variants.append(("deobfuscated", collapsed))
        extras.append(collapsed)

    if LEET_WORD_RE.search(lower):
        leet = lower.translate(LEET_MAP)
        if leet != lower:
            notes.append("Leetspeak (digits used as letters) was translated")
            variants.append(("deobfuscated", leet))
            extras.append(leet)

    ml_text = " ".join([lower] + extras)
    return {"variants": variants, "notes": notes, "ml_text": ml_text}
