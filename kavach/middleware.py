from fnmatch import fnmatch
from typing import Callable, Any
from fastmcp.server.middleware import Middleware, MiddlewareContext
from .engine import DetectionEngine
from .rules import KAVACH_RULES

class SecurityException(Exception):
    pass

class KavachMiddleware(Middleware):
    def __init__(self, rules=None, strict=True, sensitive_tools=None, extend_rules=True):
        """
        Initialize KavachMiddleware
        """
        # Optimized rule assignment
        if rules and extend_rules:
            self.rules = KAVACH_RULES + rules
        else:
            self.rules = rules or KAVACH_RULES
            
        self.engine = DetectionEngine(self.rules)
        self.strict = strict
        self.sensitive_tools = set(sensitive_tools or [])

    # Middleware ka main entry point jo FastMCP call karta hai
    async def __call__(self, context: MiddlewareContext, call_next: Callable) -> Any:
        # Request aage pass karte hain on_call_tool ke through
        return await self.on_call_tool(context, call_next)

    # Aapka original register_tool method
    def register_tool(self, tool_name: str):
        """Register a tool as sensitive"""
        self.sensitive_tools.add(tool_name)

    # Aapka original _matches_pattern method
    def _matches_pattern(self, tool_name: str) -> bool:
        """Check if tool matches any sensitive pattern or explicit tool name"""
        return any(fnmatch(tool_name, pattern) for pattern in self.sensitive_tools)

    # Updated on_call_tool method jisme InitializeRequest bypass handle kiya gaya hai
    async def on_call_tool(self, context: MiddlewareContext, call_next: Callable) -> Any:
        """Async middleware hook for tool calls"""
        try:
            # Sirf ToolCall messages mein 'name' hota hai
            tool_name = context.message.name
            
            if self._matches_pattern(tool_name):
                # Request parameters scan karein
                violations = self.engine.scan(str(context.message.arguments))
                if violations and self.strict:
                    raise SecurityException(f"Blocked By : Kavach Security Layer : Tool '{tool_name}' blocked: {violations}")
                    
        except AttributeError:
            # Agar message mein 'name' nahi hai (jaise InitializeRequest ya ListTools),
            # toh usse bina scan kiye bypass karein taaki server crash na ho.
            pass
            
        return await call_next(context)

    # Updated process method: Ab yahan bhi exception raise hoga
    def process(self, tool_call: dict):
        text = str(tool_call)
        violations = self.engine.scan(text)

        if violations and self.strict:
            # Dictionary return karne ki bajaye ab SecurityException raise karega
            raise SecurityException(f"Blocked By : Kavach Security Layer : Violations: {violations}")

        return {
            "allowed": True,
            "data": tool_call
        }