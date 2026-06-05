# Security detection engine that scans text against predefined rules
class DetectionEngine:
    """Scans text content against security rules for violations"""
    
    def __init__(self, rules):
        """Initialize with list of rules"""
        self.rules = rules

    def scan(self, text: str):
        """Scan text and return list of detected violations"""
        violations = []
        
        for rule in self.rules:
            # Check if any pattern in rule matches the text
            for pattern in rule.patterns:
                if pattern.search(text):
                    violations.append({
                        "rule": rule.id,
                        "name": rule.name,
                        "severity": rule.severity
                    })
                    break  # Move to next rule after first match
        
        return violations