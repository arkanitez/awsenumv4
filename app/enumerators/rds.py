from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])
def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    rds = session.client('rds', region_name=region, config=CFG)
    try:
        paginator = rds.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page.get('DBInstances', []) or []:
                arn = db.get('DBInstanceArn') or db['DBInstanceIdentifier']
                g.add_node(mk_id('rds', account_id, region, arn), db['DBInstanceIdentifier'], 'rds_instance', region, details={'engine': db.get('Engine'), 'PubliclyAccessible': db.get('PubliclyAccessible')})
    except ClientError as e:
        warnings.append(f'rds describe_db_instances: {e.response["Error"]["Code"]}')
