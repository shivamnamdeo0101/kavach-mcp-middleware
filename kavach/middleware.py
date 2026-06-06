# FastMCP security middleware with threat detection
from fnmatch import fnmatch
from typing import Callable, Any
from fastmcp.server.middleware import Middleware, MiddlewareContext
from .engine import DetectionEngine
from .rules import KAVACH_RULES
from .exceptions import SecurityException
from .logger.setup import get_logger, mask_sensitive_data

logger = get_logger("kavach.middleware")

class KavachMiddleware(Middleware):
    """FastMCP middleware for security threat detection and blocking"""
    
    def __init__(self, rules=None, strict=True, sensitive_tools=None, extend_rules=True):
        """Initialize middleware with security rules and configuration.
        
        Args:
            rules: Custom security rules to add
            strict: Block requests on violation if True
            sensitive_tools: Tools to scan (pattern or exact match)
            extend_rules: Extend default rules with custom ones
        """
        # Merge custom rules with defaults if extend_rules is True
        self.rules = (KAVACH_RULES + rules) if (rules and extend_rules) else (rules or KAVACH_RULES)
        self.engine = DetectionEngine(self.rules)
        self.strict = strict
        self.sensitive_tools = set(sensitive_tools or [])
        
        logger.info(f"Kavach initialized | strict={strict} | rules={len(self.rules)} | tools={len(self.sensitive_tools)}")
    
    async def __call__(self, context: MiddlewareContext, call_next: Callable) -> Any:
        """Main middleware entry point - routes to on_call_tool"""
        return await self.on_call_tool(context, call_next)

    def register_tool(self, tool_name: str):
        """Register tool for security scanning"""
        self.sensitive_tools.add(tool_name)

    def _matches_pattern(self, tool_name: str) -> bool:
        """Check if tool matches registered patterns (supports wildcards)"""
        return any(fnmatch(tool_name, pattern) for pattern in self.sensitive_tools)

    async def on_call_tool(self, context: MiddlewareContext, call_next: Callable) -> Any:
        """Scan tool calls for security violations"""
        try:
            tool_name = context.message.name
            
            # Only scan if tool is registered as sensitive
            if self._matches_pattern(tool_name):
                violations = self.engine.scan(str(context.message.arguments))
                if violations and self.strict:
                    logger.warning(f"Tool blocked | {tool_name} | violations={len(violations)}")
                    raise SecurityException(
                        f"Blocked By : Kavach Security Layer : Tool '{tool_name}' blocked: {violations}"
                    )
                elif violations:
                    logger.debug(f"Tool allowed (non-strict) | {tool_name} | violations={len(violations)}")
            else:
                logger.debug(f"Tool scanned | {tool_name}")
        except AttributeError:
            # Message type doesn't have 'name' attribute (e.g., InitializeRequest) - bypass safely
            pass
        
        return await call_next(context)

    def process(self, tool_call: dict):
        """Synchronous tool call processor with threat detection"""
        violations = self.engine.scan(str(tool_call))
        masked_call = mask_sensitive_data(str(tool_call))
        
        if violations and self.strict:
            logger.warning(f"Call blocked | violations={len(violations)} | severity={violations[0].get('severity', 'unknown')} | data={masked_call}")
            raise SecurityException(f"Blocked By : Kavach Security Layer : Violations: {violations}")
        elif violations:
            logger.debug(f"Call allowed (non-strict) | violations={len(violations)} | data={masked_call}")
        
        logger.debug(f"Call passed security scan | data={masked_call}")
        return {"allowed": True, "data": tool_call}