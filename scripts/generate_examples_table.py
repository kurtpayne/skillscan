from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

sys.path.insert(0, '/home/ubuntu/skillscan-security/src')

rules_dir = Path('/home/ubuntu/skillscan-security/src/skillscan/data/rules')
all_rules: list[dict] = []
all_chain: list[dict] = []

for yf in sorted(rules_dir.glob('*.yaml')):
    with open(yf) as f:
        data = yaml.safe_load(f)
    for r in data.get('rules', []):
        r['_source'] = yf.name
        all_rules.append(r)
    for r in data.get('chain_rules', []):
        r['_source'] = yf.name
        all_chain.append(r)

by_cat: dict[str, list[dict]] = defaultdict(list)
for r in all_rules:
    by_cat[r.get('category', 'uncategorized')].append(r)

chain_by_cat: dict[str, list[dict]] = defaultdict(list)
for r in all_chain:
    chain_by_cat[r.get('category', 'uncategorized')].append(r)

cat_labels = {
    'malware_pattern': 'Malware & Execution',
    'exfiltration': 'Exfiltration',
    'instruction_abuse': 'Instruction Abuse & Jailbreak',
    'supply_chain': 'Supply Chain',
    'obfuscation': 'Obfuscation & Evasion',
    'defense_evasion': 'Defense Evasion',
    'uncategorized': 'Other',
}

lines = [
    '# SkillScan Rule Examples',
    '',
    '> Auto-generated from `src/skillscan/data/rules/`. Do not edit by hand.',
    '> Run `python3 scripts/generate_examples_table.py` to regenerate.',
    '',
    f'**{len(all_rules)} static rules · {len(all_chain)} chain rules**',
    '',
]

lines += ['## Static Rules', '']
for cat, label in cat_labels.items():
    rules = by_cat.get(cat, [])
    if not rules:
        continue
    lines.append(f'### {label}')
    lines.append('')
    lines.append('| ID | Severity | Title | Tags |')
    lines.append('|---|---|---|---|')
    for r in sorted(rules, key=lambda x: x['id']):
        tags = ', '.join(r.get('metadata', {}).get('tags', []))
        title = r.get('title', '').replace('|', '/')
        lines.append(f"| `{r['id']}` | {r.get('severity','?')} | {title} | {tags} |")
    lines.append('')

lines += [
    '## Chain Rules', '',
    '| ID | Severity | Title | Requires | Tags |',
    '|---|---|---|---|---|',
]
for r in sorted(all_chain, key=lambda x: x['id']):
    req = ' + '.join(r.get('all_of', []))
    tags = ', '.join(r.get('metadata', {}).get('tags', []))
    title = r.get('title', '').replace('|', '/')
    lines.append(
        f"| `{r['id']}` | {r.get('severity','?')} | {title} | `{req}` | {tags} |"
    )
lines.append('')

out = Path('/home/ubuntu/skillscan-security/docs/EXAMPLES.md')
out.write_text('\n'.join(lines))
print(f"Written {len(lines)} lines to {out}")
