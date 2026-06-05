# Type definitions for Kavach security rules
from dataclasses import dataclass
from typing import List, Pattern

@dataclass
class Rule:
    """Security rule with detection patterns"""
    id: str
    name: str
    severity: str
    description: str
    patterns: List[Pattern]