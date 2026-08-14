"""Compatibility reconstruction for the missing Suricata Analyst Trainer module.

Reconstructed from the public interface used by suricata_web.py.  The web app
supplies a large supplemental/expanded question bank itself; this module
provides the original trainer API, core questions, lessons, and scoring/
adaptive-selection helpers needed to run it.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple
import random
import re


@dataclass
class Question:
    id: str
    category: str
    mode: str
    difficulty: int
    rule: str
    prompt: str
    answer_points: List[str] = field(default_factory=list)
    required_terms: List[str] = field(default_factory=list)
    accepted_terms: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    explanation: str = ""
    skills: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Be tolerant of tuple/set inputs from older trainer content.
        for name in ("answer_points", "required_terms", "accepted_terms", "hints", "skills"):
            value = getattr(self, name)
            if value is None:
                setattr(self, name, [])
            elif not isinstance(value, list):
                setattr(self, name, list(value))


def _q(
    id: str, category: str, mode: str, difficulty: int, rule: str, prompt: str,
    answer_points: Sequence[str], required_terms: Sequence[str] = (),
    accepted_terms: Sequence[str] = (), hints: Sequence[str] = (),
    explanation: str = "", skills: Sequence[str] = (),
) -> Question:
    return Question(
        id=id, category=category, mode=mode, difficulty=difficulty,
        rule=rule, prompt=prompt, answer_points=list(answer_points),
        required_terms=list(required_terms), accepted_terms=list(accepted_terms),
        hints=list(hints), explanation=explanation, skills=list(skills),
    )


# ---------------------------------------------------------------------------
# Core training content
# ---------------------------------------------------------------------------

ALL_QUESTIONS = [
    _q(
        "core001", "Network Variables", "read", 1,
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound HTTP"; sid:100001; rev:1;)',
        "Read the rule header. What traffic direction does it describe?",
        ["$HOME_NET source", "$EXTERNAL_NET destination", "outbound", "protected host"],
        accepted_terms=["home_net", "external_net", "outbound"],
        hints=["Read the left and right sides of the arrow.", "HOME_NET is the source here."],
        explanation="HOME_NET on the source side and EXTERNAL_NET on the destination side describes outbound traffic from protected hosts.",
        skills=["variables", "direction"],
    ),
    _q(
        "core002", "Network Variables", "repair", 1,
        'alert http any any -> any any (msg:"Inbound admin"; content:"/admin"; sid:100002; rev:1;)',
        "Repair this rule so it specifically describes inbound requests to protected web servers.",
        ["$EXTERNAL_NET", "$HOME_NET", "flow:established,to_server", "http.uri", "/admin"],
        required_terms=["$EXTERNAL_NET", "$HOME_NET", "http.uri"],
        accepted_terms=["inbound", "to_server", "/admin"],
        explanation="Inbound HTTP requests should be scoped from EXTERNAL_NET to HOME_NET, with request-side flow and URI matching.",
        skills=["variables", "repair", "http_buffers"],
    ),
    _q(
        "core003", "Rule Structure", "read", 1,
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SSH access"; flags:S; sid:100003; rev:1;)',
        "What are the protocol, source, destination port, and traffic direction?",
        ["tcp", "$EXTERNAL_NET", "$HOME_NET", "22", "inbound"],
        accepted_terms=["ssh", "tcp", "port 22", "external_net", "home_net"],
        explanation="The rule is TCP traffic from EXTERNAL_NET to HOME_NET on destination port 22, so it describes inbound SSH connection attempts.",
        skills=["rule_reading", "direction"],
    ),
    _q(
        "core004", "HTTP Buffers", "read", 2,
        'alert http $EXTERNAL_NET any -> $HOME_NET any (http.uri; content:"/login"; sid:100004; rev:1;)',
        "Why is http.uri preferable to an unscoped content match for a login path?",
        ["http.uri", "request path", "scoped", "reduces false positives"],
        accepted_terms=["uri", "path", "scoped", "noise"],
        explanation="http.uri limits the match to the request URI/path instead of arbitrary payload text.",
        skills=["http_buffers", "rule_reading"],
    ),
    _q(
        "core005", "HTTP Buffers", "repair", 2,
        'alert http any any -> any any (msg:"POST login"; content:"POST"; content:"/login"; sid:100005; rev:1;)',
        "Repair this rule so the method and URI are matched in their proper HTTP buffers.",
        ["http.method", "POST", "http.uri", "/login"],
        required_terms=["http.method", "http.uri"],
        accepted_terms=["post", "/login"],
        explanation="Use http.method for POST and http.uri for /login. Buffer-specific matching is more precise than raw payload matching.",
        skills=["http_buffers", "repair"],
    ),
    _q(
        "core006", "DNS Detection", "read", 2,
        'alert dns $HOME_NET any -> $EXTERNAL_NET any (dns.query; content:"bad.example"; sid:100006; rev:1;)',
        "What field is being inspected, and what does the content value represent?",
        ["dns.query", "queried domain", "bad.example"],
        accepted_terms=["dns", "query", "domain"],
        explanation="dns.query contains the queried DNS name, so the rule matches bad.example in the DNS query buffer.",
        skills=["dns", "rule_reading"],
    ),
    _q(
        "core007", "DNS Detection", "optimize", 2,
        'alert dns any any -> any any (dns.query; pcre:"/[a-z0-9]{20,}\\./i"; sid:100007; rev:1;)',
        "Why should a long-label DNS rule use behavioral context before being treated as tunneling?",
        ["rate", "source tracking", "repeated queries", "baseline", "entropy"],
        accepted_terms=["detection_filter", "by_src", "threshold", "allowlist", "known services"],
        explanation="Long DNS labels can be legitimate. Repetition, source tracking, rate, entropy, and business-service baselines provide stronger evidence.",
        skills=["dns", "thresholding", "tuning"],
    ),
    _q(
        "core008", "TLS/SNI", "repair", 2,
        'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious hostname"; http.host; content:"evil.example"; sid:100008; rev:1;)',
        "Repair the buffer so this TLS hostname detection inspects the SNI field.",
        ["tls.sni", "not http.host"],
        required_terms=["tls.sni"],
        accepted_terms=["sni", "tls", "clienthello"],
        explanation="TLS hostname evidence is in tls.sni. http.host is an HTTP header and is not the TLS SNI field.",
        skills=["tls", "sni", "repair"],
    ),
    _q(
        "core009", "TLS/SNI", "optimize", 2,
        'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious SNI"; tls.sni; content:"cdn"; nocase; sid:100009; rev:1;)',
        "Why is matching the generic string cdn usually noisy, and what should replace it?",
        ["cdn is generic", "specific FQDN", "controlled suffix", "baseline", "allowlist"],
        accepted_terms=["specific", "hostname", "domain", "context"],
        explanation="Generic SNI fragments such as cdn occur in legitimate traffic. Use specific suspicious domains/suffixes and environmental context.",
        skills=["tls", "tuning"],
    ),
    _q(
        "core010", "Flow and Direction", "read", 2,
        'alert http $EXTERNAL_NET any -> $HOME_NET any (flow:established,to_server; http.uri; content:"cmd.exe"; sid:100010; rev:1;)',
        "What does flow:established,to_server contribute to this request-side detection?",
        ["established", "to_server", "request side", "client to server"],
        accepted_terms=["request", "client", "server", "flow"],
        explanation="It limits the match to established client-to-server traffic, aligning the URI check with the HTTP request side.",
        skills=["flow", "direction"],
    ),
    _q(
        "core011", "Rule Writing", "write", 2,
        "(build full rule)",
        "Write a rule for outbound curl User-Agent traffic from protected hosts.",
        ["alert http", "$HOME_NET", "$EXTERNAL_NET", "http.user_agent", "curl", "nocase", "sid", "rev"],
        required_terms=["alert", "http", "$HOME_NET", "$EXTERNAL_NET", "http.user_agent", "curl", "sid", "rev"],
        accepted_terms=["to_server", "flow"],
        explanation='Example: alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound curl User-Agent"; flow:established,to_server; http.user_agent; content:"curl"; nocase; sid:100011; rev:1;).',
        skills=["writing", "http"],
    ),
    _q(
        "core012", "Rule Repair", "repair", 2,
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible webshell"; content:"cmd="; sid:100012; rev:1;)',
        "Repair this rule so cmd= is scoped to likely HTTP request locations and the direction is intentional.",
        ["flow:established,to_server", "http.uri", "http.request_body", "cmd=", "nocase"],
        required_terms=["http.uri"],
        accepted_terms=["http.request_body", "flow", "to_server", "cmd="],
        explanation="A stronger rule uses client-to-server flow and scopes cmd= to http.uri and/or http.request_body instead of scanning arbitrary payload content.",
        skills=["repair", "http_buffers", "webshell"],
    ),
    _q(
        "core013", "Optimization / Tuning", "optimize", 3,
        'alert tcp any any -> any any (msg:"Possible scan"; flags:S; sid:100013; rev:1;)',
        "How can a SYN rule be tuned so it detects scan-like behavior rather than normal connections?",
        ["detection_filter", "track by_src", "count", "seconds", "port spread"],
        accepted_terms=["threshold", "rate", "source", "destination"],
        explanation="A single SYN is normal. Track repeated attempts by source over time and consider destination/port spread.",
        skills=["thresholding", "tuning"],
    ),
    _q(
        "core014", "SOC Alert Triage", "capstone", 3,
        'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"Possible exploit"; flow:established,to_server; http.uri; content:"cmd.exe"; sid:100014; rev:1;)',
        "What evidence should an analyst collect before escalating or tuning this alert?",
        ["web logs", "response status", "source behavior", "follow-on activity", "authorized testing"],
        accepted_terms=["edr", "callback", "scanner", "reputation", "response"],
        explanation="Validate the request, response, source, server logs/telemetry, follow-on activity, and whether approved testing explains it.",
        skills=["triage", "workflow"],
    ),
    _q(
        "core015", "Production Detection Engineering", "optimize", 4,
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Outbound automation"; http.user_agent; content:"python"; nocase; sid:100015; rev:1;)',
        "What production context should be checked before broadly suppressing this alert?",
        ["asset role", "owner", "destination", "frequency", "known automation", "narrow allowlist"],
        accepted_terms=["baseline", "specific user-agent", "unknown hosts", "document"],
        explanation="Automation can be legitimate. Tune known-good source/destination combinations narrowly while retaining visibility for unusual hosts or destinations.",
        skills=["production", "tuning", "triage"],
    ),
]


# Aliases used by the web application for module-specific banks.
VARIABLES_AND_STRUCTURE = [q for q in ALL_QUESTIONS if q.category == "Network Variables" or q.category == "Rule Structure"]
RULE_READING = [q for q in ALL_QUESTIONS if q.mode == "read"]
OPTIMIZATION = [q for q in ALL_QUESTIONS if q.mode == "optimize"]
WRITING = [q for q in ALL_QUESTIONS if q.mode == "write"]
REPAIR = [q for q in ALL_QUESTIONS if q.mode == "repair"]


NETWORK_VARIABLES_LESSON = """
### Network Variables

`$HOME_NET` normally identifies the networks you protect, while `$EXTERNAL_NET`
represents traffic outside that protected environment.

Read the rule header before reading the options. The side of the arrow containing
`$HOME_NET` tells you which side of the conversation is considered protected.
Choose inbound or outbound direction deliberately rather than defaulting to
`any any -> any any`.

For production tuning, direction is often the first noise-reduction step:
identify the source, destination, protocol, and intended traffic path before
adding complicated content logic.
""".strip()

RULE_BUILDING_LESSON = """
### Rule Building

A Suricata rule can be understood as: action, protocol, source network/port,
direction arrow, destination network/port, then rule options.

Build detections from the traffic field that actually contains the indicator.
Use protocol-specific buffers such as `http.uri`, `http.method`,
`http.user_agent`, `dns.query`, and `tls.sni` when they are available.
""".strip()

BUFFER_LESSON = """
### Buffers

A buffer scopes a content match to a particular parsed protocol field.
For HTTP, common examples include `http.uri`, `http.method`, `http.host`,
`http.user_agent`, and `http.request_body`. DNS names belong in `dns.query`;
TLS hostnames belong in `tls.sni`.

Buffer scoping reduces accidental matches in unrelated payload data and makes
the rule easier for an analyst to explain and defend.
""".strip()

TUNING_LESSON = """
### Tuning

Do not solve noise by deleting the detection. First identify why it fires:
direction, buffer scope, indicator specificity, frequency, source/asset role,
destination, and expected business behavior.

Useful production techniques include source/destination scoping, specific
indicators, `flow:established,to_server`, rate/threshold logic, baselines,
and narrowly documented allowlists.
""".strip()


# ---------------------------------------------------------------------------
# Trainer API expected by suricata_web.py
# ---------------------------------------------------------------------------

def _question_record(progress: Dict[str, Any], q: Question) -> Dict[str, Any]:
    return progress.setdefault("questions", {}).setdefault(
        q.id,
        {"seen": 0, "correct": 0, "wrong": 0, "mastery": 0, "hints": 0},
    )


def score_answer(answer: str, q: Question) -> Tuple[bool, List[str]]:
    """Score an answer using required terms plus concept hits.

    The original web app has its own strict-mode scorer. This function is the
    normal/adaptive scorer it calls when available.
    """
    answer = (answer or "").strip().lower()
    required = [str(x).lower() for x in q.required_terms]
    accepted = [str(x).lower() for x in q.accepted_terms]
    points = [str(x).lower() for x in q.answer_points]

    missing = [term for term in required if term not in answer]
    hits = sum(1 for p in points if p in answer)
    accepted_hit = any(t in answer for t in accepted)

    # For questions with explicit required terms, all required terms are mandatory.
    # Otherwise, one meaningful concept hit is sufficient for a normal-mode answer.
    ok = not missing and (accepted_hit or hits > 0 or bool(required))
    issues = [f"Missing required element: {term}" for term in missing]
    if not ok and not issues:
        issues.append("Your answer missed the main detection concept.")
    return ok, issues


def update_stats(progress: Dict[str, Any], q: Question, ok: bool, hints_used: int = 0) -> None:
    rec = _question_record(progress, q)
    rec["seen"] += 1
    if ok:
        rec["correct"] += 1
        rec["mastery"] = min(5, rec.get("mastery", 0) + (1 if not hints_used else 0))
    else:
        rec["wrong"] += 1
        rec["mastery"] = max(0, rec.get("mastery", 0) - 1)
    rec["hints"] = rec.get("hints", 0) + int(hints_used or 0)


def global_stats(progress: Dict[str, Any]) -> Dict[str, Any]:
    qs = progress.get("questions", {})
    seen = sum(int(v.get("seen", 0)) for v in qs.values())
    correct = sum(int(v.get("correct", 0)) for v in qs.values())
    wrong = sum(int(v.get("wrong", 0)) for v in qs.values())
    mastered = sum(1 for v in qs.values() if int(v.get("mastery", 0)) >= 5)
    accuracy = round((correct / seen) * 100) if seen else 0
    return {
        "seen": seen,
        "correct": correct,
        "wrong": wrong,
        "mastered": mastered,
        "accuracy": accuracy,
    }


def _difficulty_distance(q: Question, target: int) -> int:
    return abs(int(getattr(q, "difficulty", 1)) - int(target))


def pick_questions(
    bank: Sequence[Question],
    count: int = 1,
    adaptive: bool = True,
    progress: Dict[str, Any] | None = None,
) -> List[Question]:
    """Return a small adaptive sample without requiring external dependencies."""
    bank = list(bank)
    if not bank or count <= 0:
        return []

    progress = progress or {}
    records = progress.get("questions", {})

    def weight(q: Question) -> float:
        r = records.get(q.id, {})
        seen = int(r.get("seen", 0))
        mastery = int(r.get("mastery", 0))
        wrong = int(r.get("wrong", 0))
        # Prefer unseen, weak, or recently missed questions.
        w = 1.0
        if seen == 0:
            w += 5.0
        w += max(0, 3 - mastery) * 1.5
        w += min(wrong, 4) * 1.5
        return w

    if not adaptive:
        return random.sample(bank, min(count, len(bank)))

    pool = bank[:]
    chosen: List[Question] = []
    for _ in range(min(count, len(pool))):
        weights = [weight(q) for q in pool]
        q = random.choices(pool, weights=weights, k=1)[0]
        chosen.append(q)
        pool.remove(q)
    return chosen


def explain_selection_reason(
    q: Question, progress: Dict[str, Any], bank: Sequence[Question]
) -> str:
    rec = progress.get("questions", {}).get(q.id, {})
    if not rec:
        return "Practice recommendation: this is a new question for the current session."
    if rec.get("wrong", 0) > rec.get("correct", 0):
        return "Practice recommendation: this concept has produced more misses than correct answers."
    if rec.get("mastery", 0) < 3:
        return "Practice recommendation: this skill is still developing."
    return "Practice recommendation: adaptive practice is rotating this topic for reinforcement."


__all__ = [
    "Question",
    "ALL_QUESTIONS",
    "VARIABLES_AND_STRUCTURE",
    "RULE_READING",
    "OPTIMIZATION",
    "WRITING",
    "REPAIR",
    "NETWORK_VARIABLES_LESSON",
    "RULE_BUILDING_LESSON",
    "BUFFER_LESSON",
    "TUNING_LESSON",
    "score_answer",
    "update_stats",
    "global_stats",
    "pick_questions",
    "explain_selection_reason",
]
