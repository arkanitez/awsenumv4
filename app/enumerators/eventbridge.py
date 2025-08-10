from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    eb = session.client('events', region_name=region, config=CFG)
    buses = []
    try:
        buses = eb.list_event_buses().get('EventBuses', []) or []
    except ClientError as e:
        warnings.append(f'events list_event_buses: {e.response["Error"]["Code"]}')
        return

    for b in buses:
        bus_arn = b.get('Arn'); bus_name = b.get('Name')
        g.add_node(mk_id('eventbus', account_id, region, bus_name), bus_name, 'eventbridge_bus', region)

        # Rules on this bus
        try:
            paginator = eb.get_paginator('list_rules')
            for page in paginator.paginate(EventBusName=bus_name):
                for r in page.get('Rules', []) or []:
                    rname = r['Name']
                    rule_node = mk_id('eventrule', account_id, region, rname)
                    g.add_node(rule_node, rname, 'eventbridge_rule', region)
                    g.add_edge(mk_id('edge', account_id, region, 'bus', bus_name, 'rule', rname),
                               mk_id('eventbus', account_id, region, bus_name), rule_node,
                               'has-rule', 'bind', 'resource')

                    # Targets
                    try:
                        tgts = eb.list_targets_by_rule(EventBusName=bus_name, Rule=rname).get('Targets', []) or []
                        for t in tgts:
                            arn = t.get('Arn', '')
                            if ':lambda:' in arn:
                                g.add_edge(mk_id('edge', account_id, region, 'rule', rname, 'lambda', arn),
                                           rule_node, mk_id('lambda', account_id, region, arn),
                                           'event→lambda', 'target', 'data')
                            elif ':sns:' in arn:
                                topic = arn.split(':')[-1]
                                g.add_edge(mk_id('edge', account_id, region, 'rule', rname, 'sns', topic),
                                           rule_node, mk_id('sns', account_id, region, topic),
                                           'event→sns', 'target', 'data')
                            elif ':sqs:' in arn:
                                q = arn.split(':')[-1]
                                g.add_edge(mk_id('edge', account_id, region, 'rule', rname, 'sqs', q),
                                           rule_node, mk_id('sqs', account_id, region, q),
                                           'event→sqs', 'target', 'data')
                            elif ':kinesis:' in arn:
                                s = arn.split('/')[-1]
                                g.add_edge(mk_id('edge', account_id, region, 'rule', rname, 'kinesis', s),
                                           rule_node, mk_id('kinesis', account_id, region, s),
                                           'event→kinesis', 'target', 'data')
                    except ClientError as e:
                        warnings.append(f'events list_targets_by_rule({rname}): {e.response["Error"]["Code"]}')
        except ClientError as e:
            warnings.append(f'events list_rules({bus_name}): {e.response["Error"]["Code"]}')
