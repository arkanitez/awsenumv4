from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    s3 = session.client('s3', config=CFG)
    try:
        res = s3.list_buckets()
        for b in res.get('Buckets', []):
            name = b['Name']
            # region detection
            loc = 'us-east-1'
            try:
                lr = s3.get_bucket_location(Bucket=name)
                loc = lr.get('LocationConstraint') or 'us-east-1'
            except ClientError: pass

            g.add_node(mk_id('s3', account_id, loc, name), name, 's3_bucket', loc, details={'name': name})

            # S3 -> Lambda notifications (triggers)
            try:
                notif = s3.get_bucket_notification_configuration(Bucket=name)
                for cfg in notif.get('LambdaFunctionConfigurations', []) or []:
                    lam_arn = cfg.get('LambdaFunctionArn')
                    if lam_arn:
                        g.add_edge(mk_id('edge', account_id, loc, 's3notif', name, lam_arn),
                                   mk_id('s3', account_id, loc, name),
                                   mk_id('lambda', account_id, loc, lam_arn),
                                   'event→lambda', 'trigger', 'data', details={'source': 's3-notification'})
            except ClientError as e:
                code = e.response['Error'].get('Code')
                if code not in ('NoSuchBucket','AccessDenied'):
                    warnings.append(f's3 get_bucket_notification_configuration({name}): {code}')
    except ClientError as e:
        warnings.append(f's3 list_buckets: {e.response["Error"]["Code"]}')
