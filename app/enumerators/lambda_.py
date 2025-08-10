from __future__ import annotations
from typing import List
import re
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id, add_edges_from_role_policies

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def _table_from_arn(arn: str):
    m = re.match(r'^arn:aws:dynamodb:([a-z0-9-]+):(\d+):table/([^/]+)', arn)
    if not m: return (None, None, None)
    return (m.group(1), m.group(2), m.group(3))

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    lam = session.client('lambda', region_name=region, config=CFG)
    try:
        paginator = lam.get_paginator('list_functions')
        for page in paginator.paginate():
            for fn in page.get('Functions', []) or []:
                arn = fn['FunctionArn']; name = fn['FunctionName']
                vpcid = fn.get('VpcConfig', {}).get('VpcId')
                g.add_node(mk_id('lambda', account_id, region, arn), name, 'lambda', region,
                           details={'runtime': fn.get('Runtime')},
                           parent=mk_id('vpc', account_id, region, vpcid) if vpcid else None)

                # Event source mappings => (DynamoDB Streams / SQS / Kinesis) -> Lambda
                try:
                    esms = lam.list_event_source_mappings(FunctionName=arn).get('EventSourceMappings', []) or []
                    for m in esms:
                        src = (m.get('EventSourceArn') or '')
                        label = 'event→lambda'
                        if ':dynamodb:' in src:
                            r,a,tbl = _table_from_arn(src)
                            if tbl:
                                g.add_edge(mk_id('edge', account_id, region, 'ddbstream', tbl, arn),
                                           mk_id('dynamodb', a or account_id, r or region, tbl),
                                           mk_id('lambda', account_id, region, arn),
                                           label, 'trigger', 'data', details={'source': 'esm'})
                        elif ':sqs:' in src:
                            g.add_edge(mk_id('edge', account_id, region, 'sqs', src, arn),
                                       mk_id('sqs', account_id, region, src.split(':')[-1]),
                                       mk_id('lambda', account_id, region, arn),
                                       label, 'trigger', 'data', details={'source': 'esm'})
                        elif ':kinesis:' in src:
                            g.add_edge(mk_id('edge', account_id, region, 'kinesis', src, arn),
                                       mk_id('kinesis', account_id, region, src.split('/')[-1]),
                                       mk_id('lambda', account_id, region, arn),
                                       label, 'trigger', 'data', details={'source': 'esm'})
                except ClientError as e:
                    warnings.append(f'lambda list_event_source_mappings: {e.response["Error"]["Code"]}')

                # IAM-inferred edges (who Lambda can talk to)
                role_arn = fn.get('Role')
                if role_arn:
                    add_edges_from_role_policies(session, role_arn,
                                                 mk_id('lambda', account_id, region, arn),
                                                 name, account_id, region, g, warnings)
    except ClientError as e:
        warnings.append(f'lambda list_functions: {e.response["Error"]["Code"]}')
