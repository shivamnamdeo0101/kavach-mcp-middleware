# Security detection engine that scans text against predefined rules
from .logger.setup import get_logger, mask_sensitive_data

logger = get_logger("kavach.engine")

class DetectionEngine:
    """Scans text content against security rules for violations"""
    
    def __init__(self, rules):
        """Initialize with list of rules"""
        self.rules = rules
        logger.info(f"DetectionEngine initialized | rules={len(rules)}")

    def scan(self, text: str):
        """Scan text and return list of detected violations"""
        violations = []
        masked_text = mask_sensitive_data(text)
        
        for rule in self.rules:
            # Check if any pattern in rule matches the text
            for pattern in rule.patterns:
                if pattern.search(text):
                    violations.append({
                        "rule": rule.id,
                        "name": rule.name,
                        "severity": rule.severity
                    })
                    logger.debug(f"Rule matched | {rule.id} | severity={rule.severity} | data={masked_text}")
                    break  # Move to next rule after first match
        
        return violations