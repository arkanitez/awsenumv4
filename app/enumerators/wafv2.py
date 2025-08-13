from __future__ import annotations
from typing import List
import boto3
from botocore.config import Config as BotoConfig
from ..graph import Graph
from ..iam_edges import mk_id

# WAFv2 for CloudFront is in us-east-1 scope 'CLOUDFRONT'
CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    # Only run once in us-east-1 to avoid dupes
    if region != 'us-east-1': 
        return
    waf = session.client('wafv2', region_name='us-east-1', config=CFG)
    scope = 'CLOUDFRONT'
    token = None
    while True:
        try:
            kw = {'Scope': scope}
            if token: kw['NextMarker'] = token
            resp = waf.list_web_acls(**kw)
        except Exception as e:
            warnings.append(f'wafv2 list_web_acls: {e}')
            return
        for acl in resp.get('WebACLs', []) or []:
            name = acl.get('Name'); arn = acl.get('ARN'); id_ = acl.get('Id')
            if not name or not arn: continue
            node_id = mk_id('waf', account_id, 'us-east-1', id_ or name)
            g.add_node(node_id, name, 'waf_web_acl', 'us-east-1', details={'Name': name, 'Arn': arn, 'Scope': scope})

            # associate edges to CloudFront distributions
            try:
                assoc = waf.list_resources_for_web_acl(WebACLArn=arn, ResourceType='CLOUDFRONT')
                for rarn in assoc.get('ResourceArns', []) or []:
                    dist_id = rarn.split('/')[-1]
                    cf_id = mk_id('cloudfront', account_id, 'us-east-1', dist_id)
                    g.add_edge(mk_id('edge', account_id, 'us-east-1', 'waf-cf', id_ or name, dist_id),
                               node_id, cf_id, 'protects', 'waf_association', 'security', details={})
            except Exception:
                pass
        token = resp.get('NextMarker')
        if not token: break
