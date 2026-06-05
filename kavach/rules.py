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

    Rule(
        id="dangerous-eval",
        name="Dangerous Eval/Exec Detection",
        severity="critical",
        description="Detects usage of dangerous functions like eval() and exec()",
        patterns=[
            re.compile(r"\b(eval|exec|compile)\s*\(", re.IGNORECASE),
        ],
    ),

    Rule(
        id="sql-injection-keywords",
        name="SQL Injection Patterns",
        severity="high",
        description="Detects SQL injection attempts with dangerous keywords",
        patterns=[
            re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|';|--\s|\/\*)", re.IGNORECASE),
        ],
    ),

    Rule(
        id="file-traversal",
        name="Path Traversal Attempts",
        severity="high",
        description="Detects directory traversal attempts using ../ or ..\\",
        patterns=[
            re.compile(r"(\.\./|\.\.\\)"),
        ],
    ),

    Rule(
        id="dangerous-shell-pipe",
        name="Shell Command Piping",
        severity="high",
        description="Detects dangerous shell command piping patterns",
        patterns=[
            re.compile(r"(?:^|\s)(?:\||\|\||&&)\s*(?:rm|del|drop|truncate|format)", re.IGNORECASE),
        ],
    ),
]