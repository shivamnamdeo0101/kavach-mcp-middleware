from .engine import DetectionEngine
from .rules import KAVACH_RULES

class KavachMiddleware:
    def __init__(self, rules=None, strict=True):
        self.rules = rules or KAVACH_RULES
        self.engine = DetectionEngine(self.rules)
        self.strict = strict

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