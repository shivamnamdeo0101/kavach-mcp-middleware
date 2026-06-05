# Kavach Middleware - Optimization Guide

## Current Architecture
KavachMiddleware uses two-stage filtering:
1. **Tool Pattern Matching** - `fnmatch()` for O(1) wildcard matching
2. **Content Scanning** - Regex-based rule scanning only on sensitive tools

This avoids scanning non-sensitive tools entirely.

## Quick Wins

### 1. Tool-Based Pre-filtering (Already Implemented ✅)
Only scan tools matching `sensitive_tools` patterns:
```python
middleware = KavachMiddleware(
    sensitive_tools=["filesystem.*", "aws.*"]  # Patterns via fnmatch
)
# Non-matching tools skip content scanning entirely
```

### 2. Limit Payload Size
```python
MAX_PAYLOAD_SIZE = 100_000  # 100 KB

if len(str(context.message.arguments)) > MAX_PAYLOAD_SIZE:
    raise SecurityException("Payload exceeds limit")
```

### 3. Cache Repeated Scans
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def _cached_scan(self, text: str):
    return self.engine.scan(text)
```

### 4. Priority Rule Ordering
```python
SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2}
self.rules.sort(key=lambda r: SEVERITY_PRIORITY.get(r.severity, 3))
```

## Performance Targets
- **P50**: < 1ms (with tool pre-filtering) ✅
- **P95**: < 5ms
- **Max Rules**: 50 (avoid 100+)
- **Max Payload**: 100 KB
- **Max Sensitive Tools**: 20 patterns

## Load Capacity
- **Light**: 10-50 req/sec ✅ (all approaches work)
- **Medium**: 100-200 req/sec ✅ (with tool pre-filtering)
- **High**: 500+ req/sec ✅ (+ caching + payload limits)

## Implementation Priority

1. **Priority 1** ✅ **DONE**: Tool pattern pre-filtering - only scans relevant tools
2. **Priority 2**: Payload size limit - prevents regex DoS on edge cases
3. **Priority 3**: Rule ordering by severity - faster blocking of critical threats
4. **Priority 4**: Result caching - deduplicate repeated scans
5. **Priority 5**: Extend custom rules instead of replacing - reuse KAVACH_RULES

## Monitoring Metrics

Track these to know when optimization is needed:
- Average scan time per request (target: < 1ms)
- Percentage of tools skipped by pre-filtering (target: > 70%)
- P95 latency (when it exceeds 5ms)
- Cache hit rate (if caching implemented)
- Payload size distribution
