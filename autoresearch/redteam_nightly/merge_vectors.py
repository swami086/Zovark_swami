#!/usr/bin/env python3
"""Merge new attack vectors into existing file"""
import json

# Load existing vectors
with open('/app/attack_vectors.json') as f:
    existing = json.load(f)

# Load new vectors
with open('/app/attack_vectors_new.json') as f:
    new_vectors = json.load(f)

# Get existing IDs to avoid duplicates
existing_ids = {v['id'] for v in existing}

# Add only new vectors
added = 0
for v in new_vectors:
    if v['id'] not in existing_ids:
        existing.append(v)
        added += 1

# Save merged
with open('/app/attack_vectors.json', 'w') as f:
    json.dump(existing, f, indent=2)

print(f'Added {added} new vectors')
print(f'Total vectors: {len(existing)}')
