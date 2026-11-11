---
name: Bug report
about: A missed identifier, a false positive, or a wrong score
labels: bug
---

**Never paste a real Aadhaar, PAN, GSTIN or UPI ID here.** Generate a
synthetic one instead:

```python
from pehchaan import verhoeff_digit, gstin_check_char
p = "36420577201"; print(p + str(verhoeff_digit(p)))
f = "29ABCPN1234F1Z"; print(f + gstin_check_char(f))
```

**Input** (synthetic values only)

```
```

**Scope** (column name, environment, source), if any:

**What pehchaan returned** (paste `f.score` and `f.why`):

**What you expected:**

**pehchaan version** (`python -c "import pehchaan; print(pehchaan.__version__)"`):
