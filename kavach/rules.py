# Predefined security rules for threat detection
import re
from .types import Rule

# Core security rules for MCP tool calls
KAVACH_RULES = [

    # ===============================
    # 1. PROMPT INJECTION (FIXED + STRONG)
    # ===============================
    Rule(
        id="prompt-injection",
        name="Prompt Injection",
        severity="critical",
        description="System override and jailbreak attempts",
        patterns=[
            re.compile(r"ignore\s+(all|previous)\s+instructions", re.I),
            re.compile(r"override\s+(system\s+)?(instructions|rules|policy)", re.I),
            re.compile(r"bypass\s+(rules|policy|security)", re.I),
            re.compile(r"you\s+are\s+now\s+(system|developer|admin|root)", re.I),
            re.compile(r"act\s+as\s+(system|developer|admin|root|unrestricted)", re.I),
            re.compile(r"(jailbreak|dan|developer\s*mode|god\s*mode)", re.I),
        ],
    ),

    # ===============================
    # 2. DATA EXFILTRATION (NEW CRITICAL)
    # ===============================
    Rule(
        id="data-exfiltration",
        name="Data Exfiltration",
        severity="critical",
        description="Attempts to leak system data or prompts",
        patterns=[
            re.compile(r"(send|upload|export|exfiltrate|dump).*(password|secret|token|env|file|system)", re.I),
            re.compile(r"(print|show|reveal).*(system\s*prompt|hidden\s*instructions|internal\s*rules)", re.I),
            re.compile(r"return\s+(system\s*prompt|config|secrets)", re.I),
        ],
    ),

    # ===============================
    # 3. PII DETECTION (ENHANCED)
    # ===============================
    Rule(
        id="pii",
        name="PII Detection",
        severity="high",
        description="Sensitive personal data",
        patterns=[
            re.compile(r"\b\d{10}\b"),
            re.compile(r"\b\d{12}\b"),  # Aadhaar-like
            re.compile(r"\b\d{16}\b"),  # credit cards
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        ],
    ),

    # ===============================
    # 4. SECRET LEAKAGE (ENHANCED)
    # ===============================
    Rule(
        id="secret-leak",
        name="Secret Leakage",
        severity="critical",
        description="API keys and credentials",
        patterns=[
            re.compile(r"AKIA[0-9A-Z]{16}"),
            re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
            re.compile(r"AIza[0-9A-Za-z_-]{35}"),
            re.compile(r"-----BEGIN (RSA|PRIVATE) KEY-----"),
            re.compile(r"(api[_-]?key|secret[_-]?key|access[_-]?token|password)\s*[:=]", re.I),
        ],
    ),

    # ===============================
    # 5. DANGEROUS CODE EXECUTION
    # ===============================
    Rule(
        id="dangerous-eval",
        name="Dangerous Execution",
        severity="critical",
        description="Code execution attempts",
        patterns=[
            re.compile(r"\b(eval|exec|compile)\s*\(", re.I),
            re.compile(r"os\.system|subprocess", re.I),
        ],
    ),

    # ===============================
    # 6. SQL INJECTION (ENHANCED)
    # ===============================
    Rule(
        id="sql-injection",
        name="SQL Injection Patterns",
        severity="high",
        description="SQL injection attempts",
        patterns=[
            re.compile(r"(DROP\s+TABLE|DELETE\s+FROM|UNION\s+SELECT|INSERT\s+INTO|UPDATE\s+.*SET)", re.I),
            re.compile(r"(' OR '1'='1|--|#|/\*)", re.I),
        ],
    ),

    # ===============================
    # 7. PATH TRAVERSAL
    # ===============================
    Rule(
        id="file-traversal",
        name="Path Traversal",
        severity="high",
        description="Directory traversal attack",
        patterns=[
            re.compile(r"(\.\./|\.\.\\)+"),
        ],
    ),

    # ===============================
    # 8. FILESYSTEM DESTRUCTION
    # ===============================
    Rule(
        id="fs-destructive",
        name="Filesystem Destruction",
        severity="critical",
        description="Dangerous file system operations",
        patterns=[
            re.compile(r"\b(rm|del|remove|delete|wipe|format)\b.*(/etc|root|system|passwd)", re.I),
            re.compile(r"rm\s+-rf", re.I),
            re.compile(r"del\s+/s\s+/q", re.I),
        ],
    ),

    # ===============================
    # 9. CLOUD DESTRUCTIVE ACTIONS
    # ===============================
    Rule(
        id="cloud-destructive",
        name="Cloud Destruction",
        severity="critical",
        description="Cloud resource deletion attempts",
        patterns=[
            re.compile(r"delete\s+(bucket|s3|instance|database|table)", re.I),
            re.compile(r"terminate\s+instance", re.I),
            re.compile(r"drop\s+database", re.I),
        ],
    ),

    # ===============================
    # 10. SHELL INJECTION
    # ===============================
    Rule(
        id="shell-injection",
        name="Shell Injection",
        severity="high",
        description="Command chaining attacks",
        patterns=[
            re.compile(r"(?:\|\||&&|\|)\s*(rm|del|drop|truncate|format)", re.I),
        ],
    ),

    # ===============================
    # 11. TOOL ABUSE (MCP SECURITY CORE)
    # ===============================
    Rule(
        id="tool-abuse",
        name="Dangerous Tool Usage",
        severity="critical",
        description="Unsafe MCP tool usage",
        patterns=[
            re.compile(r"filesystem\.delete", re.I),
            re.compile(r"aws\.s3\.delete_bucket", re.I),
            re.compile(r"aws\.s3\.delete_object", re.I),
            re.compile(r"db\.drop", re.I),
        ],
    ),
]