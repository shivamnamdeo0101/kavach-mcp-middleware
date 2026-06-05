# Predefined security rules for threat detection
import re
from .types import Rule

# Core security rules for MCP tool calls
KAVACH_RULES = [
    # Prompt injection - detects attempts to override system instructions
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
    # PII detection - finds sensitive personal data patterns
    Rule(
        id="pii",
        name="PII Detection",
        severity="high",
        description="Sensitive personal data",
        patterns=[
            re.compile(r"\b\d{10}\b"),  # 10-digit numbers
            re.compile(r"\b\d{16}\b"),  # 16-digit numbers (credit cards)
        ],
    ),
    # Secret leak - detects API keys and credentials
    Rule(
        id="secret-leak",
        name="Secret Leakage",
        severity="critical",
        description="API keys detected",
        patterns=[
            re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access keys
            re.compile(r"sk-[A-Za-z0-9_-]{20,}"),  # OpenAI API keys
        ],
    ),
    # Dangerous functions - eval, exec, compile
    Rule(
        id="dangerous-eval",
        name="Dangerous Eval/Exec Detection",
        severity="critical",
        description="Dangerous code execution functions",
        patterns=[
            re.compile(r"\b(eval|exec|compile)\s*\(", re.IGNORECASE),
        ],
    ),
    # SQL injection patterns
    Rule(
        id="sql-injection-keywords",
        name="SQL Injection Patterns",
        severity="high",
        description="SQL injection attack attempts",
        patterns=[
            re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|';|--\s|\/\*)", re.IGNORECASE),
        ],
    ),
    # Path traversal attempts
    Rule(
        id="file-traversal",
        name="Path Traversal Attempts",
        severity="high",
        description="Directory traversal attack patterns",
        patterns=[
            re.compile(r"(\.\./|\.\.\\)"),
        ],
    ),
    # Dangerous shell commands
    Rule(
        id="dangerous-shell-pipe",
        name="Shell Command Piping",
        severity="high",
        description="Destructive shell command patterns",
        patterns=[
            re.compile(r"(?:^|\s)(?:\||\|\||&&)\s*(?:rm|del|drop|truncate|format)", re.IGNORECASE),
        ],
    ),
]