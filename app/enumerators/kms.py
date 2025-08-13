from __future__ import annotations
from typing import List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    kms = session.client('kms', region_name=region, config=CFG)
    token = None
    while True:
        try:
            kw = {}
            if token: kw['Marker'] = token
            resp = kms.list_keys(**kw)
        except Exception as e:
            warnings.append(f'kms list_keys: {e}')
            return
        for k in resp.get('Keys', []) or []:
            key_id = k.get('KeyId'); arn = k.get('KeyArn')
            if not key_id: continue
            try:
                desc = kms.describe_key(KeyId=key_id).get('KeyMetadata', {})
                node_id = mk_id('kms', account_id, region, key_id)
                g.add_node(node_id, desc.get('Description') or key_id, 'kms_key', region, details={
                    'KeyId': key_id, 'Arn': arn, 'KeyState': desc.get('KeyState'),
                    'KeyManager': desc.get('KeyManager'), 'CustomerMasterKeySpec': desc.get('CustomerMasterKeySpec'),
                    'KeyRotationEnabled': kms.get_key_rotation_status(KeyId=key_id).get('KeyRotationEnabled', False)
                })
            except Exception:
                continue
        token = resp.get('NextMarker') or resp.get('Truncated') and resp.get('NextMarker')
        if not resp.get('Truncated'): break
