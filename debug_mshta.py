import re
raw_lower = "mshta.exe javascript:alert('test')".lower()
result = bool(re.search(r'mshta[\s:]*(?:http|vbscript|javascript)', raw_lower))
print(f"Pattern match: {result}")

# Try different patterns
patterns = [
    r'mshta[\s:]*(?:http|vbscript|javascript)',
    r'mshta.*(?:http|vbscript|javascript)',
    r'mshta\.exe.*(?:http|vbscript|javascript)',
    r'mshta',
]
for p in patterns:
    print(f"Pattern {p}: {bool(re.search(p, raw_lower))}")
