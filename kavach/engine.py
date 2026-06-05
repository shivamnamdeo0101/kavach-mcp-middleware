class DetectionEngine:
    def __init__(self, rules):
        self.rules = rules

    def scan(self, text: str):
        violations = []

        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern.search(text):
                    violations.append({
                        "rule": rule.id,
                        "name": rule.name,
                        "severity": rule.severity
                    })
                    break

        return violations