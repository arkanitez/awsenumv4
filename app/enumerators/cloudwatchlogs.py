from __future__ import annotations
from typing import List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    cwl = session.client('logs', region_name=region, config=CFG)
    token = None
    while True:
        try:
            kw = {}
            if token: kw['nextToken'] = token
            resp = cwl.describe_log_groups(**kw)
        except Exception as e:
            warnings.append(f'cloudwatchlogs describe_log_groups: {e}')
            return
        for lg in resp.get('logGroups', []) or []:
            name = lg.get('logGroupName')
            if not name: continue
            node_id = mk_id('cwl', account_id, region, name)
            details = {
                'logGroupName': name,
                'RetentionInDays': lg.get('retentionInDays'),
                'retentionInDays': lg.get('retentionInDays'),
                'kmsKeyId': lg.get('kmsKeyId'),
                'storedBytes': lg.get('storedBytes'),
            }
            g.add_node(node_id, name, 'cloudwatch_log_group', region, details=details)
        token = resp.get('nextToken')
        if not token: break
