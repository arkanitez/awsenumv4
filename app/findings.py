from __future__ import annotations
from typing import List, Dict, Any

def analyze(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    nodes = [e for e in elements if 'source' not in e['data']]
    for n in nodes:
        d = n['data']
        if d.get('type') == 'rds_instance' and d.get('details', {}).get('PubliclyAccessible'):
            findings.append({ 'id': 'finding:' + d['id'], 'severity': 'High', 'title': 'RDS instance publicly accessible', 'detail': d['label'] })
    return findings
