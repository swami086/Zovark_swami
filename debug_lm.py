import re
raw_lower = r'net use \\10.0.0.50\ADMIN$ /user:DOMAIN\admin P@ssw0rd!'.lower()
print(f"Raw: {raw_lower}")
pattern = r'net use.*admin\\\$'
result = re.search(pattern, raw_lower)
print(f"Pattern match: {result}")
