from fnmatch import fnmatch
from .engine import DetectionEngine
from .rules import KAVACH_RULES

class SecurityException(Exception):
    pass

class KavachMiddleware:
    def __init__(self, rules=None, strict=True, sensitive_tools=None, extend_rules=True):
        """
        Initialize KavachMiddleware
        
        Args:
            rules: Custom detection rules (merged with defaults if extend_rules=True)
            strict: Raise exception on violation (True) or return blocked result (False)
            sensitive_tools: Tools/patterns to protect (explicit or wildcard)
            extend_rules: If True, merge custom rules with defaults. If False, use only custom rules.
        """
        if rules and extend_rules:
            self.rules = KAVACH_RULES + rules
        elif rules:
            self.rules = rules
        else:
            self.rules = KAVACH_RULES
            
        self.engine = DetectionEngine(self.rules)
        self.strict = strict
        self.sensitive_tools = set(sensitive_tools or [])

    def register_tool(self, tool_name: str):
        """Register a tool as sensitive"""
        self.sensitive_tools.add(tool_name)

    def _matches_pattern(self, tool_name: str) -> bool:
        """Check if tool matches any sensitive pattern or explicit tool name"""
        return any(fnmatch(tool_name, pattern) for pattern in self.sensitive_tools)

    async def on_call_tool(self, context, call_next):
        """Async middleware hook for tool calls"""
        tool_name = context.message.name
        
        if self._matches_pattern(tool_name):
            violations = self.engine.scan(str(context.message.arguments))
            if violations and self.strict:
                raise SecurityException(f"Tool '{tool_name}' blocked: {violations}")
        
        return await call_next(context)

    def process(self, tool_call: dict):
        text = str(tool_call)
        violations = self.engine.scan(text)

        if violations and self.strict:
            return {
                "allowed": False,
                "reason": "Blocked by Kavach Security Layer",
                "violations": violations
            }

        return {
            "allowed": True,
            "data": tool_call
        }