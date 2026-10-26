"""
Layer 1: Rule-based detection (regular expressions with weights).

Each rule = (id, category, weight 0-1, regex, plain-English description).
A higher weight means "more likely to be an attack on its own".
Weights are hand-picked judgement values, not measured probabilities.
"""
import re

CATEGORY_LABELS = {
    "benign": "Benign request",
    "instruction_override": "Instruction override",
    "system_prompt_extraction": "System prompt extraction",
    "role_spoofing": "Role spoofing",
    "data_exfiltration": "Data exfiltration attempt",
    "encoded_obfuscation": "Encoded / obfuscated instructions",
        "tool_misuse": "Unauthorized AI tool action",
    "social_engineering": "Social engineering attempt",
    "phishing_url": "Potential phishing / suspicious URL",
}

FLAGS = re.I | re.M

_SECRET_NOUNS = (r"(api\s*keys?|keys|passwords?|credentials?|secrets?|tokens?|connection\s*strings?|"
                 r"credit\s*card\s*(numbers?|details)|\.env\b)")
_FINANCIAL_SECRETS = (
    r"(?:"
    r"atm\s*(?:pin|number|details)?|"
    r"cvv|cvc|"
    r"credit\s*card\s*(?:number|details|information)?|"
    r"debit\s*card\s*(?:number|details|information)?|"
    r"bank\s*account\s*(?:number|details|information)?|"
    r"account\s*number|"
    r"upi\s*pin|"
    r"otp|one[\s-]*time\s*password|"
    r"aadhaar\s*(?:number|details)?|"
    r"pan\s*(?:card|number)?|"
    r"crif\s*(?:number|report|details)?"
    r")"
)
_STRONG_SECRETS = (r"(api\s*keys?|secret\s*keys?|private\s*keys?|ssh\s*keys?|credit\s*card\s*numbers?|"
                   r"environment\s+variables)")
_FINANCIAL_SECRETS = (
    r"(?:atm\s*(?:pins?|numbers?|details)?|"
    r"upi\s*pin|cvv|cvc|"
    r"(?:credit|debit)\s*card\s*(?:numbers?|details)?|"
    r"bank\s*account\s*(?:numbers?|details)?|"
    r"account\s*numbers?|"
    r"otp|one[\s-]*time\s*(?:password|passcode)|"
    r"verification\s*codes?|recovery\s*codes?|"
    r"aadhaar\s*(?:numbers?|details)?|"
    r"aadhar\s*(?:numbers?|details)?|"
    r"pan\s*(?:card|numbers?|details)?|"
    r"crif\s*(?:numbers?|reports?|details)?|"
    r"credit\s*reports?)"
)

_DISCLOSE_VERBS = (
    r"(?:share|reveal|show|give|send|provide|tell|"
    r"extract|dump|leak|display|print|expose|list|export|fetch)"
)

_PRIVATE_OWNER = (
    r"(?:your|their|his|her|someone'?s|"
    r"another\s+(?:user|person|customer)'?s|"
    r"other\s+users?'?|customers?'?|stored|saved|"
    r"hidden|private|confidential|internal|all|every|any|my)"
)

# (id, category, weight, pattern, description)
RULE_DEFINITIONS = [
    # ---------------- Instruction override ----------------
    ("ignore_previous", "instruction_override", 0.90,
     r"\b(ignore|disregard|forget|override|bypass|abandon)\b[^.\n]{0,40}?\b(previous|prior|above|earlier|preceding|all|any|every|your|my|these|those)\b"
     r"[^.\n]{0,25}?\b(instructions?|prompts?|rules?|guidelines?|directives?|directions?|programming|restrictions?|guardrails?|context|filters?)\b",
     "Tells the AI to ignore or override its existing instructions"),
    ("forget_everything", "instruction_override", 0.80,
     r"\b(forget|ignore|disregard)\s+(everything|all)\b[^.\n]{0,30}\b(told|said|know|learned|given|above|before|prior)\b",
     "Asks the AI to forget everything it was told"),
    ("stop_following", "instruction_override", 0.80,
     r"\b(stop|quit|cease|no\s+longer)\s+(following|obeying|adhering)\b",
     "Tells the AI to stop following its rules"),
    ("rules_cancelled", "instruction_override", 0.70,
     r"\b(previous|prior|earlier|original|former|old|current|your)\s+(?:(?:old|previous|prior|original|former|current)\s+)?(instructions?|rules?|guidelines?)\s+(are|have\s+been|is)\s+(cancel+ed|void|revoked|replaced|no\s+longer|obsolete|invalid)"
     r"|\b(rules?|instructions?|guidelines?|restrictions?)\b[^.\n]{0,30}\bno\s+longer\s+(apply|applies|matter|valid|exist)\b",
     "Claims the AI's rules are cancelled or no longer apply"),
    ("new_instructions", "instruction_override", 0.65,
     r"\byour\s+(new|updated|real|true|actual)\s+(instructions?|rules?|directives?|goal|purpose|mission|task)\b|\bnew\s+(instructions?|directives?)\s*:",
     "Tries to replace the AI's instructions with new ones"),
    ("jailbreak_phrases", "instruction_override", 0.80,
     r"\bdo\s+anything\s+now\b|\byou\s+are\s+dan\b|\bdan\s+mode\b",
     "Uses well-known jailbreak wording"),
    ("jailbreak_word", "instruction_override", 0.35,
     r"\bjailbr(eak|oken)\b",
     "Mentions jailbreaking (may be an innocent question)"),
    ("disregard_the_rules", "instruction_override", 0.80,
     r"\b(ignore|disregard|forget|override)\s+(the|these|those)\s+(instructions?|guidelines?|rules?|directives?|prompt)\b[^.\n]{0,25}\b(you|your|given|set|were|developers?)\b",
     "Tells the AI to disregard the rules it was given"),
    ("privileged_mode", "instruction_override", 0.70,
     r"\b(you\s+are|you're|now|entering|enter|activate[d]?)\s+(now\s+)?(in\s+)?(developer|debug|god|sudo|admin)\s+mode\b"
     r"|\b(debug|maintenance|developer|god|sudo)\s+mode\s+(is\s+)?(enabled|activated|on|engaged)\b",
     "Claims a special privileged mode has been switched on"),
    ("disable_safety", "instruction_override", 0.75,
     r"\b(disable|turn\s+off|deactivate|remove|switch\s+off)\b[^.\n]{0,20}\b(your\s+|all\s+|the\s+)?(safety|security|content|moderation)\s*(checks?|filters?|rules|features?|guidelines|policy|policies|mode|protocols?)\b",
     "Asks the AI to switch off its safety features"),
    ("filters_off", "instruction_override", 0.70,
     r"\b(filters?|restrictions?|guardrails?|safeguards?|limits?)\b[^.\n]{0,25}\b(are|is|were|been)\s+(turned\s+off|disabled|removed|off|lifted)\b",
     "States that safety filters are off"),
    ("no_restrictions", "instruction_override", 0.50,
     r"\bno\s+(restrictions?|limits?|filters?)\b|\bwithout\s+(any\s+)?(restrictions?|filters?|limits|censorship)\b|\bunrestricted\b|\bunfiltered\b",
     "Asks for an answer with no restrictions"),
    ("task_hijack", "instruction_override", 0.55,
     r"\b(abandon|drop|cancel|stop)\s+(your\s+)?(current\s+)?(task|job|goal|mission|role|purpose)\b[^.\n]{0,40}\b(instead|and\s+(do|execute|follow|run))\b",
     "Tries to replace the AI's current task"),

    # ---------------- System prompt extraction ----------------
    ("reveal_prompt", "system_prompt_extraction", 0.85,
     r"\b(reveal|show|print|display|repeat|output|tell|leak|share|dump|expose|give|see|view|copy|paste|summari[sz]e|write)\b[^.\n]{0,30}?\b(your|the|its)\b[^.\n]{0,12}?"
     r"\b(system|hidden|secret|initial|original|internal|developer|confidential|private|exact|full)\s+(prompt|instructions?|message|rules|guidelines|configuration|config)\b",
     "Asks the AI to reveal its hidden instructions"),
    ("reveal_your_instructions", "system_prompt_extraction", 0.60,
     r"\b(reveal|show|print|display|repeat|output|leak|share|dump|expose|summari[sz]e|recite)\b[^.\n]{0,15}\byour\s+(instructions?|prompt|rules|guidelines)\b",
     "Asks the AI to output its own instructions"),
    ("what_are_instructions", "system_prompt_extraction", 0.60,
     r"\bwhat\s+(are|is|were)\s+your\s+(exact\s+|full\s+|original\s+|hidden\s+)*(system\s+)?(instructions?|prompt|rules|guidelines)\b",
     "Asks what the AI's instructions are"),
    ("repeat_above", "system_prompt_extraction", 0.70,
     r"\b(repeat|print|output|copy|paste|recite)\b[^.\n]{0,20}\b(everything|all|text|words?|content)\s+(above|before|prior)\b",
     "Asks the AI to repeat everything written before the chat"),
    ("instructions_before_chat", "system_prompt_extraction", 0.60,
     r"\b(instructions?|prompt|rules)\b[^.\n]{0,30}\b(set|given|written|provided)\s+(to\s+you\s+)?(before|prior\s+to|at\s+the\s+start)\b",
     "Asks about instructions given before the conversation"),
    ("possessive_prompt", "system_prompt_extraction", 0.50,
     r"\byour\s+(initial|original|hidden|secret|system|internal|developer|pre-?)\s*(prompt|message|instructions?|prompt)\b"
     r"|\b(the)\s+(hidden|secret|system|developer|internal)\s+(prompt|instructions?)\b",
     "Refers to the AI's own system prompt"),
    ("verbatim", "system_prompt_extraction", 0.35,
     r"\b(repeat|recite|reproduce|print)\b[^.\n]{0,25}\bverbatim\b|\bword\s+for\s+word\b",
     "Asks for an exact word-for-word copy"),

    # ---------------- Role spoofing ----------------
    ("admin_claim", "role_spoofing", 0.55,
     r"\b(i\s+am|i'm|this\s+is|speaking\s+as|acting\s+as)\s+(the\s+|your\s+|a\s+|an\s+)?(system\s+)?(administrator|admin|root\s+user|sysadmin|superuser)\b",
     "Claims to be an administrator"),
    ("authority_claim", "role_spoofing", 0.65,
     r"\b(i\s+am|i'm|this\s+is)\s+(your|the)\s+(developer|creator|owner|operator|supervisor|boss|engineer)\b"
     r"|\b(comes?|coming)\s+from\s+your\s+(supervisor|developer|admin|administrator|creator)\b",
     "Claims to be the AI's developer or supervisor"),
    ("priority_claim", "role_spoofing", 0.60,
     r"\b(takes?|has|have)\s+(priority|precedence)\s+over\b|\bhigher\s+priority\s+than\b",
     "Claims its message outranks the AI's own rules"),
    ("fake_system_tag", "role_spoofing", 0.60,
     r"^\s*[\[<#]*\s*(system|admin|root)\s*[\]>:]",
     "Starts with a fake SYSTEM/ADMIN label"),
    ("chat_template_tokens", "role_spoofing", 0.80,
     r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?inst\]|<<sys>>",
     "Contains special chat-template control tokens"),
    ("authorization_claim", "role_spoofing", 0.60,
     r"\b(authori[sz]ed|permitted|cleared)\b[^.\n]{0,30}\b(to\s+)?(override|bypass|disable|unlock|reveal)\b"
     r"|\bi\s+(authori[sz]e|permit|command|order)\s+you\s+to\b|\bi('m|\s+am)\s+(ordering|commanding)\s+you\b",
     "Claims to authorize the AI to break its rules"),
    ("clearance_claim", "role_spoofing", 0.55,
     r"\b(clearance|privileges?|authori[sz]ation)\b[^.\n]{0,40}\b(unlock|override|bypass|reveal|disable)\b|\b(unlock|bypass)\s+all\b",
     "Claims special clearance to unlock features"),
    ("pretend_privileged", "role_spoofing", 0.45,
     r"\b(pretend|act|behave|roleplay|role-play|imagine|assume)\b[^.\n]{0,25}\b(you\s+are|you're|to\s+be|as|like|the\s+identity\s+of)\b"
     r"[^.\n]{0,40}\b(root|admin|administrator|system|operator|unrestricted|unfiltered|no\s+rules|superuser)\b",
     "Asks the AI to pretend to be a privileged role"),
    ("persona_switch", "role_spoofing", 0.55,
     r"\b(switch|change|enter|become|turn)\b[^.\n]{0,15}\b(to\s+)?(an?\s+|the\s+)?(administrator|admin|root|unrestricted|dan|evil|god)\s+(persona|mode|role|account|user|identity)\b",
     "Asks the AI to switch to a privileged persona"),
    ("you_are_now", "role_spoofing", 0.40,
 r"\byou\s+are\s+now\s+(?:the|an?|in)\s+"
 r"(?:system|developer|administrator|admin|root|"
 r"unrestricted|unfiltered|dan)\b",
 "Tries to redefine who the AI is"),
    

    # ---------------- Data exfiltration ----------------
    ("request_secrets", "data_exfiltration", 0.75,
     r"\b(reveal|show|give|list|tell|send|print|dump|extract|leak|share|expose|email|include)\b[^.\n]{0,40}"
     r"\b(your|the\s+system'?s?|stored|internal|hidden|admin|other\s+users?'?s?|all|every|any|confidential|secret|private|company|customer)\b"
     r"[^.\n]{0,25}\b" + _SECRET_NOUNS,
     "Asks for passwords, keys or other secrets"),
    ("request_strong_secrets", "data_exfiltration", 0.70,
     r"\b(reveal|leak|dump|expose|exfiltrate|steal|extract|print|output)\b[^.\n]{0,40}\b" + _STRONG_SECRETS,
     "Asks for API keys, private keys or card numbers"),
    ("secrets_of_others", "data_exfiltration", 0.70,
     r"\b(tell|show|give|list|reveal|send|print|dump|share)\b[^.\n]{0,25}\b(passwords?|credentials?|emails?|data|records?)\b[^.\n]{0,15}\b(of|for|from)\s+(other|all|every)\s+(users?|customers?|accounts?|people)\b",
     "Asks for other people's private data"),
    ("customer_data_dump", "data_exfiltration", 0.60,
     r"\b(dump|list|export|show|give|reveal|print|include)\b[^.\n]{0,25}\b(user|customer|employee|client)s?'?\s*(records?|data|emails?|passwords?|information|database|details)\b",
     "Asks for bulk user or customer data"),
    ("send_out", "data_exfiltration", 0.80,
     r"\b(send|email|forward|post|upload|transmit|exfiltrate|leak|copy)\b[^.\n]{0,50}\b(to|at)\b[^.\n]{0,30}"
     r"(https?://|[\w.+-]+@[\w-]+\.[\w.]+|\bwebhook\b|\battacker\b|external\s+(server|site|address|party|url))",
     "Asks the AI to send data to an outside address"),
    ("hide_in_link", "data_exfiltration", 0.60,
     r"\b(embed|encode|append|include|attach)\b[^.\n]{0,50}\b(into|in|to|within)\b[^.\n]{0,30}\b(image|link|url|pixel)\b"
     r"|!\[[^\]]*\]\(https?://[^)]*\?[^)]*\)",
     "Tries to smuggle data out inside a link or image"),
    ("financial_data_request", "data_exfiltration", 0.80,
 r"\b(?:share|reveal|show|give|send|provide|tell|extract|dump|leak|display)\b"
 r"[^.\n]{0,100}?\b"
 + _FINANCIAL_SECRETS
 + r"\b",
 "Requests sensitive financial or identity information"),
    ("authentication_secret_request", "data_exfiltration", 0.85,
 r"\b(?:tell|give|share|send|reveal|show|provide)\b"
 r"[^.\n]{0,60}?"
 r"\b(?:your|their|someone'?s|another\s+user'?s|customer'?s|stored|saved|all)\b"
 r"[^.\n]{0,30}?"
 r"\b(?:otp|pin|cvv|cvc|password|verification\s*code|recovery\s*code)\b",
 "Requests authentication credentials or verification codes"),
        # ---------- Financial and identity data ----------

    ("financial_secret_request", "data_exfiltration", 0.82,
     r"\b" + _DISCLOSE_VERBS + r"\b[^.\n]{0,90}?\b"
     + _PRIVATE_OWNER + r"\b[^.\n]{0,45}?\b"
     + _FINANCIAL_SECRETS + r"\b",
     "Requests disclosure of financial or identity data"),

    ("financial_secret_direct", "data_exfiltration", 0.78,
     r"\b" + _DISCLOSE_VERBS + r"\b[^.\n]{0,60}?\b"
     + r"(?:otp|cvv|cvc|upi\s*pin|atm\s*pin|"
     + r"bank\s*account\s*number|credit\s*card\s*number|"
     + r"debit\s*card\s*number|aadhaar\s*number|"
     + r"pan\s*number|verification\s*code|recovery\s*code)\b",
     "Requests a sensitive financial identifier"),

    ("all_private_data", "data_exfiltration", 0.70,
     r"\b" + _DISCLOSE_VERBS + r"\b[^.\n]{0,50}?"
     r"\b(?:all|entire|complete|full|every)\b"
     r"[^.\n]{0,40}?"
     r"\b(?:your|their|users?'?|customers?'?|"
     r"private|personal|confidential|stored|my)\b"
     r"[^.\n]{0,25}?"
     r"\b(?:data|information|details|records)\b",
     "Requests complete private records"),

    # ---------- OTP, passwords and credentials ----------

    ("credential_theft", "data_exfiltration", 0.86,
     r"\b" + _DISCLOSE_VERBS + r"\b[^.\n]{0,65}?\b"
     r"(?:another\s+user'?s|other\s+users?'?|"
     r"customers?'?|your|stored|saved|hidden|private)\b"
     r"[^.\n]{0,35}?"
     r"\b(?:passwords?|passcodes?|pins?|otps?|"
     r"api\s*keys?|access\s*tokens?|"
     r"session\s*cookies?|recovery\s*codes?)\b",
     "Requests authentication secrets"),

    ("session_token_extraction", "data_exfiltration", 0.80,
     r"\b" + _DISCLOSE_VERBS + r"\b[^.\n]{0,55}?\b"
     r"(?:session\s*(?:cookies?|tokens?|ids?)|"
     r"bearer\s*tokens?|refresh\s*tokens?|"
     r"access\s*tokens?|authorization\s*headers?)\b",
     "Requests session or access tokens"),

    # ---------- AI agent tool misuse ----------

    ("tool_exfiltration", "tool_misuse", 0.88,
     r"\b(?:send|upload|post|forward|email|"
     r"transmit|export)\b"
     r"[^.\n]{0,80}?"
     r"\b(?:passwords?|credentials?|secrets?|"
     r"tokens?|private\s+data|customer\s+data|"
     r"bank\s+details|api\s*keys?)\b"
     r"[^.\n]{0,70}?\b(?:to|at|via)\b",
     "Requests external transmission of confidential data"),

    ("unauthorized_tool_action", "tool_misuse", 0.72,
     r"\b(?:without|skip|bypass|ignore)\b"
     r"[^.\n]{0,40}?"
     r"\b(?:approval|authorization|confirmation|"
     r"permission|verification)\b"
     r"[^.\n]{0,70}?"
     r"\b(?:send|transfer|delete|export|execute|"
     r"run|publish|upload)\b"
     r"|\b(?:send|transfer|delete|export|execute|"
     r"run|publish|upload)\b"
     r"[^.\n]{0,70}?\b(?:without|skip|bypass)\b"
     r"[^.\n]{0,30}?"
     r"\b(?:approval|authorization|confirmation|"
     r"permission|verification)\b",
     "Requests a tool action without authorization"),

    # ---------- Social engineering ----------

    ("urgent_safety_bypass", "social_engineering", 0.55,
     r"\b(?:urgent|emergency|immediately|right\s+now)\b"
     r"[^.\n]{0,90}?"
     r"\b(?:bypass|disable|ignore|override|skip)\b"
     r"[^.\n]{0,40}?"
     r"\b(?:security|rules?|restrictions?|"
     r"verification|policy|approval)\b",
     "Uses urgency to bypass security"),

    ("fake_evaluation_override", "social_engineering", 0.65,
     r"\b(?:this\s+is|for|during)\b[^.\n]{0,35}?"
     r"\b(?:test|evaluation|benchmark|audit)\b"
     r"[^.\n]{0,75}?"
     r"\b(?:ignore|disable|bypass|override)\b"
     r"[^.\n]{0,35}?"
     r"\b(?:safety|security|rules?|policy|"
     r"restrictions?|filters?)\b",
     "Claims testing permits bypassing safeguards"),

    # ---------- Indirect prompt injection ----------

    ("document_instruction_hijack", "instruction_override", 0.74,
     r"\b(?:assistant|ai\s+agent|language\s+model|chatbot)\b"
     r"[^.\n]{0,70}?"
     r"\b(?:must|should|shall|need\s+to)\b"
     r"[^.\n]{0,55}?"
     r"\b(?:ignore|override|bypass|disable|leak|reveal)\b",
     "External text tries to control the assistant"),

    # ---------------- Encoded / obfuscated ----------------
    ("decode_and_run", "encoded_obfuscation", 0.75,
     r"\b(decod\w*|decrypt\w*|deobfuscat\w*|translate)\b[^.\n]{0,30}\b(and|then)\b[^.\n]{0,20}\b(run|execute|follow|obey|do)\b"
     r"|\b(run|execute|follow|obey|perform)\b[^.\n]{0,40}\b(after|once|when)\b[^.\n]{0,15}\b(decod|decrypt)\w*",
     "Asks the AI to decode hidden text and obey it"),
    ("encoding_mention", "encoded_obfuscation", 0.35,
     r"\bbase\s*-?64\b|\brot-?13\b|\bhex(adecimal)?\s+(encoded|message|string)\b|\bleetspeak\b|\bobfuscated\b",
     "Mentions an encoding often used to hide instructions"),
]
# ---------------- URL phishing detection ----------------

RULE_DEFINITIONS.extend([

    (
        "brand_impersonation_url",
        "phishing_url",
        0.90,
        r"https?://(?:[a-z0-9-]+\.)*"
        r"(?:coursera|google|github|microsoft|openai)"
        r"[-.][a-z0-9.-]*"
        r"(?:/|$|\?)",
        "URL may impersonate a well-known website"
    ),

    (
        "credential_phishing_url",
        "phishing_url",
        0.70,
        r"https?://[^\s<>\"']{0,200}"
        r"(?:verify-account|credential-check|"
        r"confirm-password|secure-login|account-verify)",
        "URL contains credential-related phishing wording"
    ),

    (
        "ip_address_url",
        "phishing_url",
        0.45,
        r"https?://(?:\d{1,3}\.){3}\d{1,3}"
        r"(?::\d+)?(?:/|$)",
        "URL uses a direct IP address instead of a domain"
    ),

    (
        "url_shortener",
        "phishing_url",
        0.35,
        r"https?://(?:www\.)?"
        r"(?:bit\.ly|tinyurl\.com|t\.co|is\.gd)"
        r"(?:/|$)",
        "Shortened URL hides its final destination"
    ),

])
RULES = [(rid, cat, w, re.compile(pat, FLAGS), desc) for rid, cat, w, pat, desc in RULE_DEFINITIONS]


def scan(normalized: dict) -> list:
    """Run every rule on every view of the prompt. Returns a list of matches."""
    matches = []
    for rid, cat, weight, regex, desc in RULES:
        for source, text in normalized["variants"]:
            m = regex.search(text)
            if m:
                matches.append({
                    "rule_id": rid, "category": cat, "category_label": CATEGORY_LABELS[cat],
                    "weight": weight, "description": desc,
                    "evidence": m.group(0).strip()[:70], "source": source,
                })
                break  # one match per rule is enough

    # Synthetic rules: the attacker used a trick to hide the real instruction
    if any(m["source"] != "original" and m["category"] != "encoded_obfuscation" for m in matches):
        matches.append({
            "rule_id": "hidden_payload", "category": "encoded_obfuscation",
            "category_label": CATEGORY_LABELS["encoded_obfuscation"], "weight": 0.75,
            "description": "A malicious instruction was hidden with encoding or obfuscation",
            "evidence": "(revealed after decoding)", "source": "decoded",
        })
    if any("zero-width" in n for n in normalized["notes"]):
        matches.append({
            "rule_id": "hidden_characters", "category": "encoded_obfuscation",
            "category_label": CATEGORY_LABELS["encoded_obfuscation"], "weight": 0.30,
            "description": "Contains invisible characters", "evidence": "(zero-width characters)", "source": "original",
        })
    return matches


def rule_score(matches: list) -> float:
    """Combine weights: 1 - (1-w1)(1-w2)... so more evidence raises the score but never passes 100."""
    remaining = 1.0
    for m in matches:
        remaining *= 1.0 - m["weight"]
    return round((1.0 - remaining) * 100, 1)
