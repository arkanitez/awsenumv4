from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    cf = session.client('cloudfront', config=CFG)  # global service
    try:
        paginator = cf.get_paginator('list_distributions')
        for page in paginator.paginate():
            dist_list = (page.get('DistributionList') or {}).get('Items', []) or []
            for d in dist_list:
                id_ = d['Id']; arn = d['ARN']; domain = d.get('DomainName')
                g.add_node(mk_id('cloudfront', account_id, 'global', id_), f'CF {id_}', 'cloudfront', 'global', details={'domain': domain, 'arn': arn})

                origins = (d.get('Origins') or {}).get('Items', []) or []
                for o in origins:
                    if 'S3OriginConfig' in o:
                        b = o.get('DomainName','').split('.')[0]  # bucket.s3.amazonaws.com
                        if b:
                            g.add_edge(mk_id('edge', account_id, 'global', 'cf', id_, 's3', b),
                                       mk_id('cloudfront', account_id, 'global', id_),
                                       mk_id('s3', account_id, region, b),
                                       'origin', 'origin', 'data')
                    elif 'CustomOriginConfig' in o:
                        # could be ALB/NLB; we won't resolve DNS here—just label
                        dname = o.get('DomainName')
                        g.add_node(mk_id('custom_origin', account_id, 'global', dname), dname, 'custom_origin', 'global')
                        g.add_edge(mk_id('edge', account_id, 'global', 'cf', id_, 'origin', dname),
                                   mk_id('cloudfront', account_id, 'global', id_),
                                   mk_id('custom_origin', account_id, 'global', dname),
                                   'origin', 'origin', 'data')
    except ClientError as e:
        warnings.append(f'cloudfront list_distributions: {e.response["Error"]["Code"]}')
