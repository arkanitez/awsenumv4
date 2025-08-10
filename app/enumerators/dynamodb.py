from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])
def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    ddb = session.client('dynamodb', region_name=region, config=CFG)
    try:
        paginator = ddb.get_paginator('list_tables')
        for page in paginator.paginate():
            for t in page.get('TableNames', []) or []:
                g.add_node(mk_id('dynamodb', account_id, region, t), t, 'dynamodb_table', region)
    except ClientError as e:
        warnings.append(f'dynamodb list_tables: {e.response["Error"]["Code"]}')
