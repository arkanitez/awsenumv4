from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    elb = session.client('elbv2', region_name=region, config=CFG)
    try:
        lbs = elb.describe_load_balancers().get('LoadBalancers', [])
        for lb in lbs:
            arn = lb['LoadBalancerArn']; name = lb['LoadBalancerName']; scheme = lb.get('Scheme'); vpcid = lb.get('VpcId')
            g.add_node(mk_id('lb', account_id, region, arn), f"{name}", 'load_balancer', region, details={'scheme': scheme}, parent=mk_id('vpc', account_id, region, vpcid) if vpcid else None)
            listeners = elb.describe_listeners(LoadBalancerArn=arn).get('Listeners', [])
            for lst in listeners:
                proto = lst.get('Protocol'); port = lst.get('Port')
                ext = mk_id('ext', account_id, region, 'internet') if scheme == 'internet-facing' else mk_id('vpc', account_id, region, vpcid)
                g.add_node(ext, 'Internet' if scheme=='internet-facing' else f'VPC {vpcid}', 'external', region)
                g.add_edge(mk_id('edge', account_id, region, arn, str(port)), ext, mk_id('lb', account_id, region, arn), f'{proto}:{port}', 'listener', 'network')
            tgs = elb.describe_target_groups(LoadBalancerArn=arn).get('TargetGroups', [])
            for tg in tgs:
                tgarn = tg['TargetGroupArn']
                g.add_node(mk_id('tg', account_id, region, tgarn), tg.get('TargetGroupName','tg'), 'target_group', region, details={'protocol': tg.get('Protocol'), 'port': tg.get('Port')})
                g.add_edge(mk_id('edge', account_id, region, arn, tgarn), mk_id('lb', account_id, region, arn), mk_id('tg', account_id, region, tgarn), 'lb→tg', 'bind', 'resource')
    except ClientError as e:
        warnings.append(f'elbv2: {e.response["Error"]["Code"]}')
