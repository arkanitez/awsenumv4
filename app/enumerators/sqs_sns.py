from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    # SNS
    sns = session.client('sns', region_name=region, config=CFG)
    try:
        for t in sns.list_topics().get('Topics', []) or []:
            arn = t['TopicArn']; name = arn.split(':')[-1]
            g.add_node(mk_id('sns', account_id, region, name), name, 'sns_topic', region)
            # Subscriptions: topic -> (lambda/sqs/http)
            try:
                subs = sns.list_subscriptions_by_topic(TopicArn=arn).get('Subscriptions', []) or []
                for s in subs:
                    prot = s.get('Protocol'); endpoint = s.get('Endpoint')
                    if prot == 'lambda' and endpoint:
                        g.add_edge(mk_id('edge', account_id, region, 'sns', name, 'lambda', endpoint),
                                   mk_id('sns', account_id, region, name),
                                   mk_id('lambda', account_id, region, endpoint),
                                   'sns→lambda', 'subscription', 'data')
                    elif prot == 'sqs' and endpoint:
                        qname = endpoint.split(':')[-1]
                        g.add_node(mk_id('sqs', account_id, region, qname), qname, 'sqs_queue', region)
                        g.add_edge(mk_id('edge', account_id, region, 'sns', name, 'sqs', qname),
                                   mk_id('sns', account_id, region, name),
                                   mk_id('sqs', account_id, region, qname),
                                   'sns→sqs', 'subscription', 'data')
            except ClientError: pass
    except ClientError as e:
        warnings.append(f'sns list_topics: {e.response["Error"]["Code"]}')

    # SQS
    sqs = session.client('sqs', region_name=region, config=CFG)
    try:
        for q in (sqs.list_queues().get('QueueUrls', []) or []):
            qname = q.split('/')[-1]
            g.add_node(mk_id('sqs', account_id, region, qname), qname, 'sqs_queue', region)
    except ClientError as e:
        # Some accounts with no SQS permissions
        code = e.response['Error'].get('Code', 'error')
        if code not in ('AccessDenied',):
            warnings.append(f'sqs list_queues: {code}')
