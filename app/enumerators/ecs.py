from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id, add_edges_from_role_policies

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    ecs = session.client('ecs', region_name=region, config=CFG)
    try:
        clusters = ecs.list_clusters().get('clusterArns', []) or []
        for c in clusters:
            g.add_node(mk_id('ecs_cluster', account_id, region, c), c.split('/')[-1], 'ecs_cluster', region)
            services = ecs.list_services(cluster=c).get('serviceArns', []) or []
            for s in services:
                g.add_node(mk_id('ecs_service', account_id, region, s), s.split('/')[-1], 'ecs_service', region)
                g.add_edge(mk_id('edge', account_id, region, c, s),
                           mk_id('ecs_cluster', account_id, region, c),
                           mk_id('ecs_service', account_id, region, s),
                           'has-service', 'attach', 'resource')
                try:
                    desc = ecs.describe_services(cluster=c, services=[s]).get('services', []) or []
                    for sd in desc:
                        td = sd.get('taskDefinition')
                        if td:
                            tdd = session.client('ecs', region_name=region, config=CFG).describe_task_definition(taskDefinition=td)['taskDefinition']
                            role = tdd.get('taskRoleArn')
                            if role:
                                add_edges_from_role_policies(session, role,
                                    mk_id('ecs_service', account_id, region, s),
                                    s.split('/')[-1], account_id, region, g, warnings)
                except ClientError as e:
                    warnings.append(f'ecs describe_services: {e.response["Error"]["Code"]}')
    except ClientError as e:
        warnings.append(f'ecs list_clusters/services: {e.response["Error"]["Code"]}')
