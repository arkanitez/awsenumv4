from __future__ import annotations
import os
from typing import Any, List, Tuple, Dict
import boto3
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import orjson

from .graph import Graph
from .reachability import derive_reachability
from .findings import analyze as analyze_findings
from .enumerators import ec2, elbv2, lambda_, apigwv2, s3, sqs_sns, dynamodb, rds, eks, ecs
from .enumerators import eventbridge, cloudfront

DEFAULT_REGION = os.environ.get('DEFAULT_REGION', 'ap-southeast-1')

def json_response(obj: Any) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(obj)))

app = FastAPI()
app.mount('/ui', StaticFiles(directory=os.path.join(os.path.dirname(__file__), 'ui')), name='ui')

@app.get('/', response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), 'ui', 'index.html'), 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())

def build_session(ak: str | None, sk: str | None, st: str | None, region: str) -> boto3.Session:
    if ak and sk:
        return boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=st,
            region_name=region
        )
    return boto3.Session(region_name=region)

def _enumerate_one_region(sess: boto3.Session, account_id: str, region: str) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    """Run all enumerators for a single region and return (elements, warnings, findings)."""
    warnings: List[str] = []
    g = Graph()

    services = [
        ('ec2', ec2.enumerate),
        ('elbv2', elbv2.enumerate),

        # Ensure downstream refs exist first
        ('dynamodb', dynamodb.enumerate),
        ('s3', s3.enumerate),
        ('sqs_sns', sqs_sns.enumerate),

        ('lambda', lambda_.enumerate),
        ('apigwv2', apigwv2.enumerate),
        ('eventbridge', eventbridge.enumerate),
        ('cloudfront', cloudfront.enumerate),

        ('rds', rds.enumerate),
        ('eks', eks.enumerate),
        ('ecs', ecs.enumerate),
    ]

    # Very simple per-service delta counter (best-effort)
    service_counts: Dict[str, int] = {}

    for name, fn in services:
        before = 0
        try:
            # If Graph.elements() is cheap, we can count; otherwise ignore errors
            try:
                before = len(list(g.elements()))
            except Exception:
                before = 0
            fn(sess, account_id, region, g, warnings)
        except Exception as e:
            warnings.append(f'{name} failed: {e}')
        finally:
            try:
                after = len(list(g.elements()))
                service_counts[name] = max(0, after - before)
            except Exception:
                # If counting fails (e.g., elements() is a generator), don’t block enumeration
                pass

    # Derived reachability edges
    try:
        for e in derive_reachability(g):
            g.add_edge(**e)
    except Exception as e:
        warnings.append(f'derive_reachability failed: {e}')

    # ---- IMPORTANT FIX: materialize once; safe to iterate multiple times
    elements: List[Dict[str, Any]] = list(g.elements())

    # Findings can now safely iterate
    findings = analyze_findings(elements)

    # Basic counts for visibility (does not consume elements)
    try:
        total_nodes = sum(1 for el in elements if 'source' not in (el.get('data') or {}))
        total_edges = sum(1 for el in elements if 'source' in (el.get('data') or {}))
        warnings.insert(0, f'Enumerated region {region}: nodes={total_nodes}, edges={total_edges}, per_service={service_counts}')
    except Exception:
        warnings.insert(0, f'Enumerated region {region}: elements={len(elements)}')

    return elements, warnings, findings

def _list_enabled_regions(sess: boto3.Session) -> List[str]:
    # Try API; if blocked, return a sensible default list.
    try:
        ec2c = sess.client('ec2')
        out = ec2c.describe_regions(AllRegions=False)
        regs = [r['RegionName'] for r in out.get('Regions', [])]
        return sorted(regs)
    except Exception:
        # Fallback: common commercial regions
        return [
            'us-east-1','us-east-2','us-west-1','us-west-2',
            'eu-west-1','eu-west-2','eu-central-1',
            'ap-south-1','ap-southeast-1','ap-southeast-2','ap-northeast-1'
        ]

@app.post('/enumerate')
async def enumerate_api(req: Request):
    payload = await req.json()
    ak = (payload.get('access_key_id') or '').strip() or None
    sk = (payload.get('secret_access_key') or '').strip() or None
    st = (payload.get('session_token') or '').strip() or None
    region = (payload.get('region') or DEFAULT_REGION).strip()
    scan_all = bool(payload.get('scan_all'))

    sess = build_session(ak, sk, st, region)

    warnings: List[str] = []
    account_id = 'self'
    try:
        me = sess.client('sts').get_caller_identity()
        account_id = me.get('Account') or 'self'
    except Exception as e:
        warnings.append(f'sts get_caller_identity failed: {e}')

    # Single region enumeration
    elements, w_reg, findings = _enumerate_one_region(sess, account_id, region)
    warnings.extend(w_reg)

    # If empty and the client asked to scan all regions, do it now
    scanned_regions = [region]
    if scan_all and not elements:
        regions = [r for r in _list_enabled_regions(sess) if r != region]
        for r in regions:
            rsess = build_session(ak, sk, st, r)
            el2, w2, f2 = _enumerate_one_region(rsess, account_id, r)
            elements.extend(el2)
            warnings.extend(w2)
            # findings is a list of dicts; naive de-dupe by string repr is fine
            for f in f2:
                if f not in findings:
                    findings.append(f)
            scanned_regions.append(r)

    return json_response({
        'elements': elements,
        'warnings': warnings,
        'findings': findings,
        'region': region,
        'scanned_regions': scanned_regions
    })
