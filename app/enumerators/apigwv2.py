from __future__ import annotations
from typing import List
import re
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)
def mk_id(*parts: str) -> str: return ":".join([p for p in parts if p])

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    api = session.client('apigatewayv2', region_name=region, config=CFG)
    try:
        apis = api.get_apis().get('Items', []) or []
        for a in apis:
            api_id = a['ApiId']; proto = a.get('ProtocolType')
            g.add_node(mk_id('apigw2', account_id, region, api_id), f'{proto} API {api_id}', 'api_gw_v2', region, details={'endpoint': a.get('ApiEndpoint')})
            routes = api.get_routes(ApiId=api_id).get('Items', []) or []
            ints = api.get_integrations(ApiId=api_id).get('Items', []) or []
            imap = {i['IntegrationId']: i for i in ints}
            for r in routes:
                rid = r['RouteId']; key = r.get('RouteKey'); iid = r.get('Target','').split('/')[-1]
                g.add_node(mk_id('apigw2-route', account_id, region, api_id, rid), key or rid, 'api_gw_v2_route', region, parent=mk_id('apigw2', account_id, region, api_id))
                if iid and iid in imap:
                    integ = imap[iid]; uri = integ.get('IntegrationUri') or ''
                    g.add_node(mk_id('integration', account_id, region, api_id, iid), 'Integration', 'integration', region, parent=mk_id('apigw2', account_id, region, api_id))
                    g.add_edge(mk_id('edge', account_id, region, 'route', rid, iid), mk_id('apigw2-route', account_id, region, api_id, rid), mk_id('integration', account_id, region, api_id, iid), 'route→integration', 'bind', 'resource')
                    if '/functions/' in uri:
                        m = re.search(r'/functions/(arn:aws:lambda:[^/]+)/invocations', uri)
                        if m:
                            lam_arn = m.group(1)
                            g.add_edge(mk_id('edge', account_id, region, 'integration', iid, 'lambda', lam_arn), mk_id('integration', account_id, region, api_id, iid), mk_id('lambda', account_id, region, lam_arn), 'invokes', 'invoke', 'data')
    except ClientError as e:
        warnings.append(f'apigwv2: {e.response["Error"]["Code"]}')
