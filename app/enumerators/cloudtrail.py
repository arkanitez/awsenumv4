from __future__ import annotations
from typing import List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    ct = session.client('cloudtrail', region_name=region, config=CFG)
    try:
        trails = ct.describe_trails(includeShadowTrails=True).get('trailList', [])
    except Exception as e:
        warnings.append(f'cloudtrail describe_trails: {e}')
        return
    for t in trails:
        name = t.get('Name'); home = t.get('HomeRegion') or region
        if not name: continue
        try:
            st = ct.get_trail_status(Name=name)
        except Exception:
            st = {}
        node_id = mk_id('cloudtrail', account_id, home, name)
        details = {
            'Name': name,
            'HomeRegion': home,
            'IsMultiRegionTrail': t.get('IsMultiRegionTrail', False),
            'LogFileValidationEnabled': t.get('LogFileValidationEnabled', False),
            'KmsKeyId': t.get('KmsKeyId'),
            'S3BucketName': t.get('S3BucketName'),
            'CloudWatchLogsLogGroupArn': t.get('CloudWatchLogsLogGroupArn'),
            'Status': st.get('IsLogging') and 'ENABLED' or 'DISABLED',
        }
        g.add_node(node_id, name, 'cloudtrail_trail', home, details=details)

        # Edges: to CWL, KMS (if present)
        lg_arn = t.get('CloudWatchLogsLogGroupArn')
        if lg_arn:
            lg_name = lg_arn.split(':')[-1].split(':log-group:')[-1]
            lg_id = mk_id('cwl', account_id, home, lg_name)
            g.add_edge(mk_id('edge', account_id, home, 'trail-cwl', name, lg_name),
                       node_id, lg_id, 'logs to', 'trail_logs', 'logging', details={})
        kms_arn = t.get('KmsKeyId')
        if kms_arn:
            key_id = kms_arn.split('/')[-1]
            kms_id = mk_id('kms', account_id, home, key_id)
            g.add_edge(mk_id('edge', account_id, home, 'trail-kms', name, key_id),
                       node_id, kms_id, 'encrypts with', 'kms', 'security', details={})
