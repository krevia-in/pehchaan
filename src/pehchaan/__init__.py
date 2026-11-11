"""pehchaan - find Indian identifiers in text, with checksums and context.

    >>> from pehchaan import scan, Scope
    >>> for f in scan("PAN: ABCPN1234F", Scope(field="CUST_PAN_NO")):
    ...     print(f.score, f.hit.kind.value, f.hit.masked)
    100 pan ABCXXXXX4F
"""

from .checksums import gstin_check_char, gstin_ok, verhoeff_digit, verhoeff_ok
from .detectors import Certainty, Hit, Kind
from .scoring import Finding, Scope, scan, scan_rows, scan_text

__version__ = "0.1.1"

__all__ = [
    "Certainty", "Finding", "Hit", "Kind", "Scope",
    "gstin_check_char", "gstin_ok", "scan", "scan_rows", "scan_text",
    "verhoeff_digit", "verhoeff_ok", "__version__",
]
