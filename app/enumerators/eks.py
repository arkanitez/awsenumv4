from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])
def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    eks = session.client('eks', region_name=region, config=CFG)
    try:
        names = eks.list_clusters().get('clusters', []) or []
        for name in names:
            d = eks.describe_cluster(name=name)['cluster']
            vpcid = d.get('resourcesVpcConfig', {}).get('vpcId')
            g.add_node(mk_id('eks', account_id, region, name), name, 'eks_cluster', region)
            if vpcid:
                g.add_edge(mk_id('edge', account_id, region, 'eks', name, vpcid), mk_id('eks', account_id, region, name), mk_id('vpc', account_id, region, vpcid), 'in-vpc', 'attach', 'resource')
    except ClientError as e:
        warnings.append(f'eks list/describe: {e.response["Error"]["Code"]}')
