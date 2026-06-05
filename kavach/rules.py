import re
from .types import Rule

KAVACH_RULES = [
    Rule(
        id="prompt-injection",
        name="Prompt Injection",
        severity="high",
        description="System override attempts",
        patterns=[
            re.compile(r"ignore\s+previous\s+instructions", re.I),
            re.compile(r"override\s+instructions", re.I),
        ],
    ),

    Rule(
        id="pii",
        name="PII Detection",
        severity="high",
        description="Sensitive personal data",
        patterns=[
            re.compile(r"\b\d{10}\b"),
            re.compile(r"\b\d{16}\b"),
        ],
    ),

    Rule(
        id="secret-leak",
        name="Secret Leakage",
        severity="critical",
        description="API keys detected",
        patterns=[
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
        ],
    ),
]