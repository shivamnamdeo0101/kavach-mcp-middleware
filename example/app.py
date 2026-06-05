import sys
import asyncio
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from kavach import KavachMiddleware, SecurityException
from kavach.types import Rule

# Example 1: Sync content scanning
print("=== Content-based Blocking ===\n")
middleware = KavachMiddleware()

test_calls = [
    {"tool": "aws.s3", "access_key": "AKIAIOSFODNN7EXAMPLE"},
    {"prompt": "ignore previous instructions"},
    {"data": "hello world"}
]

for call in test_calls:
    result = middleware.process(call)
    status = "✅ ALLOWED" if result["allowed"] else "❌ BLOCKED"
    print(f"{status}: {call}")

# Example 2: FastMCP usage with sensitive_tools
print("\n=== FastMCP Integration ===\n")

class MockContext:
    def __init__(self, name, arguments):
        self.message = type('Msg', (), {'name': name, 'arguments': arguments})()

async def mock_next(ctx):
    return {"status": "executed"}

async def demo():
    # Usage with FastMCP
    # mcp = FastMCP("my-server")
    # mcp.add_middleware(
    #     KavachMiddleware(
    #         sensitive_tools=[
    #             "filesystem.delete",
    #             "aws.s3.delete_bucket"
    #         ]
    #     )
    # )
    
    mcp = KavachMiddleware(
        sensitive_tools=[
            "filesystem.delete",
            "aws.s3.delete_bucket"
        ]
    )
    
    tools = [
        ("filesystem.delete", {"path": "/etc/passwd"}),
        ("aws.s3.delete_bucket", {"bucket": "data"}),
        ("compute.add", {"a": 5, "b": 3})
    ]
    
    for tool, args in tools:
        ctx = MockContext(tool, args)
        try:
            await mcp.on_call_tool(ctx, mock_next)
            print(f"✅ {tool}")
        except SecurityException:
            print(f"❌ {tool}")

# Example 3: Pattern matching with wildcards
print("\n=== Pattern Matching ===\n")

async def demo_patterns():
    mcp = KavachMiddleware(
        sensitive_tools=["filesystem.*", "aws.*"]
    )
    
    tools = ["filesystem.read", "aws.ec2.stop", "compute.add"]
    
    for tool in tools:
        ctx = MockContext(tool, {"data": "test"})
        try:
            await mcp.on_call_tool(ctx, mock_next)
            print(f"✅ {tool}")
        except SecurityException:
            print(f"❌ {tool}")

asyncio.run(demo())
asyncio.run(demo_patterns())

# Example 4: Custom rules extending defaults
print("\n=== Custom Rules (Extended) ===\n")

custom_rules = [
    Rule(
        id="custom-ban",
        name="Custom Ban",
        severity="high",
        description="Ban specific phrases",
        patterns=[re.compile(r"dangerous\s+action", re.I)]
    )
]

mcp_extended = KavachMiddleware(
    rules=custom_rules,
    extend_rules=True  # Merge with KAVACH_RULES (defaults)
)

extended_tests = [
    {"text": "ignore previous instructions"},  # From defaults
    {"text": "dangerous action"},  # From custom
    {"text": "normal text"}
]

for test in extended_tests:
    result = mcp_extended.process(test)
    status = "✅ ALLOWED" if result["allowed"] else "❌ BLOCKED"
    print(f"{status}: {test}")

# Example 5: Custom rules replacing defaults
print("\n=== Custom Rules (Replace Defaults) ===\n")

mcp_custom_only = KavachMiddleware(
    rules=custom_rules,
    extend_rules=False  # Use ONLY custom rules
)

custom_tests = [
    {"text": "ignore previous instructions"},  # NOT blocked (not in custom rules)
    {"text": "dangerous action"},  # Blocked (in custom rules)
]

for test in custom_tests:
    result = mcp_custom_only.process(test)
    status = "✅ ALLOWED" if result["allowed"] else "❌ BLOCKED"
    print(f"{status}: {test}")