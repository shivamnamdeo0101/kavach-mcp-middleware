"""Centralized logger configuration"""
import logging
import re

# Global flags
_logging_enabled = True
_masking_enabled = True

class LoggingFilter(logging.Filter):
    """Filter to check if logging is enabled"""
    def filter(self, record):
        return _logging_enabled

def enable_logging(enabled: bool = True):
    """Enable or disable logging globally"""
    global _logging_enabled
    _logging_enabled = enabled
    status = "enabled" if enabled else "disabled"
    print(f"[KAVACH] Logging {status}")

def is_logging_enabled() -> bool:
    """Check if logging is enabled"""
    return _logging_enabled

def enable_masking(enabled: bool = True):
    """Enable or disable sensitive data masking"""
    global _masking_enabled
    _masking_enabled = enabled
    status = "enabled" if enabled else "disabled"
    print(f"[KAVACH] Masking {status}")

def is_masking_enabled() -> bool:
    """Check if masking is enabled"""
    return _masking_enabled

def mask_sensitive_data(text: str) -> str:
    """Mask sensitive data patterns"""
    if not _masking_enabled or not isinstance(text, str):
        return text
    
    # Mask API keys
    text = re.sub(r'(AKIA|sk-|api[_-]?key)[^\s]{10,}', r'\1***', text, flags=re.I)
    # Mask tokens
    text = re.sub(r'(bearer|token)[=:\s]+[^\s]{10,}', r'\1 ***', text, flags=re.I)
    # Mask credit cards
    text = re.sub(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', '****-****-****-****', text)
    # Mask passwords
    text = re.sub(r'(password|passwd)[=:\s]+[^\s,}]+', r'\1=***', text, flags=re.I)
    # Mask access_key
    text = re.sub(r'(access_key|secret)[=:\s]+[^\s,}]+', r'\1=***', text, flags=re.I)
    
    return text

def get_logger(name: str = "kavach") -> logging.Logger:
    """Get configured logger instance"""
    logger = logging.getLogger(name)
    
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        
        handler = logging.StreamHandler()
        handler.addFilter(LoggingFilter())
        formatter = logging.Formatter(
            "[%(levelname)s] %(asctime)s | %(message)s",
            datefmt="%H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

