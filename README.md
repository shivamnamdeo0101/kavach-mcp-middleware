# Kavach - MCP Security Middleware

Security middleware for Model Context Protocol (MCP) that detects and blocks malicious tool calls using pattern-based rule scanning.

**Built by [Shivam Namdeo](https://www.linkedin.com/in/shivamnamdeo0101/)** | [PyPI Package](https://pypi.org/project/kavach-mcp/)

## Quick Start

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Run the example
cd example
python3 app.py
```

## Architecture

**Core Components:**

- **`middleware.py`** - `KavachMiddleware`: Main entry point. Processes tool calls and returns allow/block decisions.
- **`engine.py`** - `DetectionEngine`: Scans text against rules and collects violations.
- **`rules.py`** - `KAVACH_RULES`: Rule definitions for detecting prompt injection, PII, API keys, etc.
- **`types.py`** - `Rule`: Data class defining rule structure (id, name, severity, patterns).

## How It Works

```python
from kavach import KavachMiddleware

middleware = KavachMiddleware()

# Process any tool call
result = middleware.process({
    "tool": "aws.s3",
    "access_key": "AKIAIOSFODNN7EXAMPLE"
})

# Returns: {"allowed": False, "violations": [...]}
```

**Flow:**
1. Tool call is converted to string
2. `DetectionEngine` scans text against all rule patterns (regex)
3. If violations found and strict mode enabled → blocked
4. Otherwise → allowed

## Rules

Detects:
- **Prompt Injection** - "ignore previous instructions", "override instructions"
- **Secret Leakage** - AWS keys (AKIA...), OpenAI keys (sk-...)
- **PII** - 10/16 digit sequences

Add custom rules in `rules.py`:
```python
Rule(
    id="custom-rule",
    name="Rule Name",
    severity="high",
    patterns=[re.compile(r"pattern")]
)
```

## Usage

```python
# Allow all (strict=False)
middleware = KavachMiddleware(strict=False)

# Use custom rules
custom_rules = [Rule(...)]
middleware = KavachMiddleware(rules=custom_rules)
```

## Project Structure

```
kavach-mcp-middleware/
├── kavach/
│   ├── __init__.py       # Package exports
│   ├── middleware.py     # Main middleware class
│   ├── engine.py         # Detection logic
│   ├── rules.py          # Security rules
│   └── types.py          # Data classes
└── example/
    └── app.py            # Example usage
```

## Contributing

We'd love to get more features and improvements! Please feel free to:

- **Add new detection rules** in `kavach/rules.py`
- **Improve the detection engine** in `kavach/engine.py`
- **Submit bug fixes and enhancements** via pull requests
- **Suggest new security patterns** to detect

All contributions are welcome! 🚀