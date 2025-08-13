from __future__ import annotations
from typing import List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    cfg = session.client('config', region_name=region, config=CFG)
    try:
        recs = cfg.describe_configuration_recorders().get('ConfigurationRecorders', [])
        status = cfg.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])
        chans = cfg.describe_delivery_channels().get('DeliveryChannels', [])
    except Exception as e:
        warnings.append(f'config describe_*: {e}')
        return

    status_by_name = {s.get('name'): s for s in status}
    chan = chans[0] if chans else {}
    for r in recs:
        name = r.get('name') or 'default'
        st = status_by_name.get(name, {})
        node_id = mk_id('config', account_id, region, name)
        details = {
            'name': name,
            'recordingGroup': r.get('recordingGroup') or {},
            'recording': {'recording': st.get('recording', False), 'lastStatus': st.get('lastStatus')},
            'deliveryChannel': {'s3BucketName': chan.get('s3BucketName'),
                                's3KeyPrefix': chan.get('s3KeyPrefix'),
                                'snsTopicARN': chan.get('snsTopicARN')},
            'KmsKeyId': chan.get('kmsKeyArn') or chan.get('kmsKeyId')
        }
        g.add_node(node_id, f'ConfigRecorder:{name}', 'config_recorder', region, details=details)

        # Edges: to CWL (none), to S3 bucket if set, to KMS
        b = chan.get('s3BucketName')
        if b:
            s3_id = mk_id('s3', account_id, region, b)
            g.add_edge(mk_id('edge', account_id, region, 'config-s3', name, b),
                       node_id, s3_id, 'delivers to', 'delivery', 'logging', details={})
        kms_arn = details.get('KmsKeyId')
        if kms_arn:
            key_id = kms_arn.split('/')[-1]
            kms_id = mk_id('kms', account_id, region, key_id)
            g.add_edge(mk_id('edge', account_id, region, 'config-kms', name, key_id),
                       node_id, kms_id, 'encrypts with', 'kms', 'security', details={})
