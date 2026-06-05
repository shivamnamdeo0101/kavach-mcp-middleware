# Kavach - MCP Security Middleware

Security middleware for Model Context Protocol (MCP) that detects and blocks malicious tool calls using pattern-based rule scanning.

**Built by [Shivam Namdeo](https://www.linkedin.com/in/shivamnamdeo0101/)** | [PyPI Package](https://pypi.org/project/kavach-mcp/) | [Use Cases](https://github.com/shivamnamdeo0101/kavach-mcp-middleware-use-cases) 

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

### Sync: Content-based Blocking
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

### Async: FastMCP Middleware Integration
```python
from fastmcp import FastMCP
from kavach import KavachMiddleware

mcp = FastMCP("my-server")
mcp.add_middleware(
    KavachMiddleware(
        sensitive_tools=[
            "filesystem.delete",
            "aws.*",           # wildcard patterns
            "database.execute"
        ]
    )
)
```

**Flow:**
1. Tool call intercepted by `on_call_tool()` middleware hook
2. Tool name matched against `sensitive_tools` patterns
3. If matched, `DetectionEngine` scans arguments against rules
4. If violations found and strict mode enabled → raises `SecurityException`
5. Otherwise → chain to next middleware

## Default Security Rules

- **Prompt Injection** → Detects attempts to override system instructions.
- **PII Detection** → Detects phone numbers and card numbers.
- **Secret Leakage** → Detects exposed API keys and credentials.
- **Dangerous Eval/Exec** → Detects unsafe code execution patterns.
- **SQL Injection** → Detects malicious database commands.
- **Path Traversal** → Detects unauthorized file access attempts.
- **Shell Command Abuse** → Detects dangerous shell command chaining and piping.


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

### Option 1: Default Rules Only
```python
middleware = KavachMiddleware()
```

### Option 2: Extend Defaults with Custom Rules
```python
from kavach.types import Rule
import re

custom_rules = [
    Rule(
        id="custom-ban",
        name="Custom Ban",
        severity="high",
        description="Ban specific phrases",
        patterns=[re.compile(r"dangerous\s+action", re.I)]
    )
]

middleware = KavachMiddleware(
    rules=custom_rules,
    extend_rules=True  # Merge with KAVACH_RULES (default)
)
```

### Option 3: Replace Defaults with Custom Rules
```python
middleware = KavachMiddleware(
    rules=custom_rules,
    extend_rules=False  # Use ONLY custom rules
)
```

### Option 4: Control Tool Access
```python
# Allow violations in non-sensitive tools
middleware = KavachMiddleware(strict=False)

# Protect specific tools
middleware = KavachMiddleware(
    sensitive_tools=["filesystem.delete", "aws.s3.delete_bucket"]
)
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

## API Reference

### `KavachMiddleware.__init__()`
| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rules` | `List[Rule]` | `KAVACH_RULES` | Custom detection rules |
| `strict` | `bool` | `True` | Raise exception (True) or return blocked result (False) |
| `sensitive_tools` | `List[str]` | `[]` | Tools to protect (exact match or wildcard patterns) |
| `extend_rules` | `bool` | `True` | Merge custom rules with defaults (True) or replace (False) |

### Methods
- `process(tool_call: dict)` - Sync content scanning. Returns `{"allowed": bool, ...}`
- `async on_call_tool(context, call_next)` - FastMCP async middleware hook
- `register_tool(tool_name: str)` - Add tool to sensitive_tools at runtime

## Contributing

We'd love to get more features and improvements! Please feel free to:

- **Add new detection rules** in `kavach/rules.py`
- **Improve the detection engine** in `kavach/engine.py`
- **Submit bug fixes and enhancements** via pull requests
- **Suggest new security patterns** to detect

All contributions are welcome! 🚀
