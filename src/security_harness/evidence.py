"""Best-effort context redaction. Default audit payloads contain only digests."""
from __future__ import annotations
import re
_KEY = re.compile(r"password|secret|token|credential|authorization|api[_-]?key|private[_-]?key",re.I)
_TEXT = re.compile(r"-----BEGIN[^\n]*PRIVATE KEY-----.*?-----END[^\n]*PRIVATE KEY-----|\b(?:sk-[\w-]{16,}|AKIA[0-9A-Z]{16})\b|(?i:bearer)\s+[\w.\-/+=]+",re.S)
def redact(value):
    if isinstance(value,dict):
        return {k:"[REDACTED]" if _KEY.search(str(k)) and not (k in {"token_start","token_end"} and type(v) is int) else redact(v) for k,v in value.items()}
    if isinstance(value,(list,tuple)): return [redact(x) for x in value]
    if isinstance(value,str): return _TEXT.sub("[REDACTED]",value)[:8192]
    return value
