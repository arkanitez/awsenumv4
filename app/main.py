from __future__ import annotations

import os
import io
import json
from typing import Any, Dict, List, Tuple, Optional
from urllib.parse import quote_plus

import boto3
from botocore.config import Config
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
import orjson

from .graph import Graph
# Your existing enumerators (keep these imports aligned with your repo)
from .enumerators import ec2, elbv2, lambda_ as enum_lambda, apigwv2, s3, sqs_sns, dynamodb, rds, eks, ecs, eventbridge, cloudfront

# If you added reachability/findings elsewhere, keep them; otherwise these can be omitted.
try:
    from .reachability import derive_reachability
except Exception:
    def derive_reachability(g: Graph):
        return []
try:
    from .findings import analyze as analyze_findings
except Exception:
    def analyze_findings(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return []

DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-southeast-1")

def json_response(obj: Any) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(obj)))

app = FastAPI()
app.mount('/ui', StaticFiles(directory=os.path.join(os.path.dirname(__file__), 'ui')), name='ui')

@app.get('/', response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), 'ui', 'index.html'), 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())

def _boto_cfg() -> Config:
    # Reasonable retry/backoff for bursty UI clicks
    return Config(retries={'max_attempts': 6, 'mode': 'adaptive'}, user_agent_extra='awsenumv4')

def build_session(ak: Optional[str], sk: Optional[str], st: Optional[str], region: str) -> boto3.Session:
    if ak and sk:
        return boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=st,
            region_name=region,
        )
    return boto3.Session(region_name=region)

def _safe_get(d: Dict[str, Any], *path: str) -> Optional[Any]:
    cur = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur

def _id_last(data_id: str) -> str:
    # id like "apigwv2:acct:region:api-abc123" -> "api-abc123"
    return (data_id or '').split(':')[-1]

def _augment_download_links(elements: List[Dict[str, Any]], ak: Optional[str], sk: Optional[str], st: Optional[str]) -> None:
    """For known node types, add details.links with backend download routes."""
    for el in elements:
        if not isinstance(el, dict): 
            continue
        if el.get("group") != "nodes":
            continue
        data = el.get("data") or {}
        ntype = data.get("type")
        region = data.get("region") or DEFAULT_REGION
        details = data.setdefault("details", {})
        links = details.setdefault("links", [])
        # helper to add link
        def add(title: str, href: str, download: bool = True):
            links.append({"title": title, "href": href, "download": download})

        # AWS console deeplink (handy)
        arn = details.get("arn")
        if arn and isinstance(arn, str):
            add("Open in AWS Console", f"/download/console?arn={quote_plus(arn)}")

        # Lambda function code zip
        if ntype == "lambda":
            fn_arn = details.get("arn")
            fn_name = details.get("name") or data.get("label")
            if fn_arn or fn_name:
                qs = f"region={quote_plus(region)}"
                if fn_arn: qs += f"&functionArn={quote_plus(fn_arn)}"
                if fn_name: qs += f"&functionName={quote_plus(fn_name)}"
                if ak: qs += f"&ak={quote_plus(ak)}"
                if sk: qs += f"&sk={quote_plus(sk)}"
                if st: qs += f"&st={quote_plus(st)}"
                add("Download Lambda code (zip)", f"/download/lambda-code?{qs}")

        # Lambda layer code zip (if you enumerate layers as nodes/type)
        if ntype == "lambda_layer":
            layer_arn = details.get("arn") or data.get("label")
            version = details.get("version") or details.get("Version")
            if layer_arn and version:
                qs = f"region={quote_plus(region)}&layerArn={quote_plus(layer_arn)}&version={quote_plus(str(version))}"
                if ak: qs += f"&ak={quote_plus(ak)}"
                if sk: qs += f"&sk={quote_plus(sk)}"
                if st: qs += f"&st={quote_plus(st)}"
                add("Download Lambda layer (zip)", f"/download/lambda-layer?{qs}")

        # API Gateway v2 (HTTP/WebSocket) export: JSON bundle (api + routes + integrations + stages)
        if ntype == "api_gw_v2":
            # Try from details or id
            api_id = details.get("api_id") or _id_last(data.get("id") or "")
            if api_id:
                qs = f"region={quote_plus(region)}&apiId={quote_plus(api_id)}"
                if ak: qs += f"&ak={quote_plus(ak)}"
                if sk: qs += f"&sk={quote_plus(sk)}"
                if st: qs += f"&st={quote_plus(st)}"
                add("Download API Gateway (HTTP/WebSocket) export (json)", f"/download/apigwv2-export?{qs}")

        # DynamoDB table describe JSON
        if ntype == "dynamodb_table":
            tab_arn = details.get("arn")
            tab_name = details.get("name") or data.get("label")
            if tab_arn or tab_name:
                qs = f"region={quote_plus(region)}"
                if tab_arn: qs += f"&tableArn={quote_plus(tab_arn)}"
                if tab_name: qs += f"&tableName={quote_plus(tab_name)}"
                if ak: qs += f"&ak={quote_plus(ak)}"
                if sk: qs += f"&sk={quote_plus(sk)}"
                if st: qs += f"&st={quote_plus(st)}"
                add("Download DynamoDB table (describe json)", f"/download/dynamodb-table?{qs}")

        # CloudFront distribution config JSON
        if ntype == "cloudfront":
            # global service; region ignored
            dist_id = details.get("id") or _id_last(data.get("id") or "")
            if dist_id:
                qs = f"id={quote_plus(dist_id)}"
                if ak: qs += f"&ak={quote_plus(ak)}"
                if sk: qs += f"&sk={quote_plus(sk)}"
                if st: qs += f"&st={quote_plus(st)}"
                add("Download CloudFront distribution config (json)", f"/download/cloudfront-config?{qs}")

def _enumerate_one_region(sess: boto3.Session, account_id: str, region: str) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    warnings: List[str] = []
    g = Graph()

    services = [
        ('ec2', ec2.enumerate),
        ('elbv2', elbv2.enumerate),
        ('dynamodb', dynamodb.enumerate),
        ('s3', s3.enumerate),
        ('sqs_sns', sqs_sns.enumerate),
        ('lambda', enum_lambda.enumerate),
        ('apigwv2', apigwv2.enumerate),
        ('eventbridge', eventbridge.enumerate),
        ('cloudfront', cloudfront.enumerate),
        ('rds', rds.enumerate),
        ('eks', eks.enumerate),
        ('ecs', ecs.enumerate),
    ]

    service_counts: Dict[str, int] = {}

    for name, fn in services:
        before = len(list(g.elements()))
        try:
            fn(sess, account_id, region, g, warnings)
        except Exception as e:
            warnings.append(f'{name} failed: {e}')
        finally:
            after = len(list(g.elements()))
            service_counts[name] = max(0, after - before)

    # Derived network inference (if present)
    try:
        for e in derive_reachability(g):
            g.add_edge(**e)
    except Exception as e:
        warnings.append(f'derive_reachability failed: {e}')

    elements: List[Dict[str, Any]] = list(g.elements())
    findings = analyze_findings(elements)

    try:
        total_nodes = sum(1 for el in elements if 'source' not in (el.get('data') or {}))
        total_edges = sum(1 for el in elements if 'source' in (el.get('data') or {}))
        warnings.insert(0, f'Enumerated region {region}: nodes={total_nodes}, edges={total_edges}, per_service={service_counts}')
    except Exception:
        warnings.insert(0, f'Enumerated region {region}: elements={len(elements)}')

    return elements, warnings, findings

def _list_enabled_regions(sess: boto3.Session) -> List[str]:
    try:
        ec2c = sess.client('ec2', config=_boto_cfg())
        out = ec2c.describe_regions(AllRegions=False)
        return sorted([r['RegionName'] for r in out.get('Regions', [])])
    except Exception:
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
        me = sess.client('sts', config=_boto_cfg()).get_caller_identity()
        account_id = me.get('Account') or 'self'
    except Exception as e:
        warnings.append(f'sts get_caller_identity failed: {e}')

    elements, w_reg, findings = _enumerate_one_region(sess, account_id, region)
    warnings.extend(w_reg)

    scanned_regions = [region]
    if scan_all and not elements:
        regions = [r for r in _list_enabled_regions(sess) if r != region]
        for r in regions:
            rsess = build_session(ak, sk, st, r)
            el2, w2, f2 = _enumerate_one_region(rsess, account_id, r)
            elements.extend(el2)
            warnings.extend(w2)
            for f in f2:
                if f not in findings:
                    findings.append(f)
            scanned_regions.append(r)

    # Augment with download links (needs creds for signing)
    _augment_download_links(elements, ak, sk, st)

    return json_response({
        'elements': elements,
        'warnings': warnings,
        'findings': findings,
        'region': region,
        'scanned_regions': scanned_regions
    })

# --------------------------
# Download endpoints
# --------------------------

def _session_from_qs(ak: Optional[str], sk: Optional[str], st: Optional[str], region: Optional[str]) -> boto3.Session:
    return build_session(ak, sk, st, region or DEFAULT_REGION)

@app.get('/download/lambda-code')
async def download_lambda_code(
    region: str = Query(...),
    functionArn: Optional[str] = Query(None),
    functionName: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_from_qs(ak, sk, st, region)
    lam = sess.client('lambda', region_name=region, config=_boto_cfg())
    fn = functionArn or functionName
    if not fn:
        return JSONResponse({"error": "functionArn or functionName required"}, status_code=400)
    try:
        meta = lam.get_function(FunctionName=fn)
        loc = _safe_get(meta, "Code", "Location")
        if not loc:
            return JSONResponse({"error": "No code location available"}, status_code=404)
        # redirect to AWS pre-signed URL
        return RedirectResponse(url=loc, status_code=307)
    except Exception as e:
        return JSONResponse({"error": f"lambda get_function failed: {e}"}, status_code=500)

@app.get('/download/lambda-layer')
async def download_lambda_layer(
    region: str = Query(...),
    layerArn: str = Query(...),
    version: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_from_qs(ak, sk, st, region)
    lam = sess.client('lambda', region_name=region, config=_boto_cfg())
    try:
        out = lam.get_layer_version(LayerName=layerArn, VersionNumber=int(version))
        loc = _safe_get(out, "Content", "Location")
        if not loc:
            return JSONResponse({"error": "No layer content location available"}, status_code=404)
        return RedirectResponse(url=loc, status_code=307)
    except Exception as e:
        return JSONResponse({"error": f"lambda get_layer_version failed: {e}"}, status_code=500)

@app.get('/download/apigwv2-export')
async def download_apigwv2_export(
    region: str = Query(...),
    apiId: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_from_qs(ak, sk, st, region)
    agw = sess.client('apigatewayv2', region_name=region, config=_boto_cfg())
    bundle: Dict[str, Any] = {}
    try:
        bundle['api'] = agw.get_api(ApiId=apiId)
        # paginate routes
        routes: List[Dict[str, Any]] = []
        token = None
        while True:
            kw = {"ApiId": apiId}
            if token:
                kw["NextToken"] = token
            resp = agw.get_routes(**kw)
            routes.extend(resp.get("Items", []))
            token = resp.get("NextToken")
            if not token:
                break
        bundle['routes'] = routes

        # integrations
        integrations: List[Dict[str, Any]] = []
        token = None
        while True:
            kw = {"ApiId": apiId}
            if token:
                kw["NextToken"] = token
            resp = agw.get_integrations(**kw)
            integrations.extend(resp.get("Items", []))
            token = resp.get("NextToken")
            if not token:
                break
        bundle['integrations'] = integrations

        # stages
        stages = agw.get_stages(ApiId=apiId).get("Items", [])
        bundle['stages'] = stages

        data = orjson.dumps(bundle)
        filename = f"apigwv2-{apiId}.json"
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return JSONResponse({"error": f"apigatewayv2 export failed: {e}"}, status_code=500)

@app.get('/download/dynamodb-table')
async def download_dynamodb_table(
    region: str = Query(...),
    tableArn: Optional[str] = Query(None),
    tableName: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    if not tableArn and not tableName:
        return JSONResponse({"error": "tableArn or tableName required"}, status_code=400)
    sess = _session_from_qs(ak, sk, st, region)
    ddb = sess.client('dynamodb', region_name=region, config=_boto_cfg())
    try:
        # Prefer name; if only ARN, extract name at the end: arn:aws:dynamodb:region:acct:table/Name
        name = tableName
        if not name and tableArn:
            # Works for both table:Name and table/Name forms
            if ":table/" in tableArn:
                name = tableArn.split(":table/")[-1].split("/")[0]
            elif ":table:" in tableArn:
                name = tableArn.split(":table:")[-1].split("/")[0]
        if not name:
            return JSONResponse({"error": "could not parse table name"}, status_code=400)
        desc = ddb.describe_table(TableName=name)
        data = orjson.dumps(desc)
        filename = f"dynamodb-{name}.json"
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return JSONResponse({"error": f"dynamodb describe_table failed: {e}"}, status_code=500)

@app.get('/download/cloudfront-config')
async def download_cloudfront_config(
    id: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    # CloudFront is global; region ignored
    sess = build_session(ak, sk, st, "us-east-1")
    cf = sess.client('cloudfront', config=_boto_cfg())
    try:
        out = cf.get_distribution_config(Id=id)
        data = orjson.dumps(out)
        filename = f"cloudfront-{id}-config.json"
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return JSONResponse({"error": f"cloudfront get_distribution_config failed: {e}"}, status_code=500)

@app.get('/download/console')
async def open_in_console(arn: str = Query(...)):
    """Simple redirect to the AWS console deep link when we can infer it from ARN."""
    # Minimal mapping; expand as needed
    try:
        parts = arn.split(':')
        if len(parts) < 6:
            return JSONResponse({"error": "unsupported arn format"}, status_code=400)
        service = parts[2]
        region = parts[3]
        account = parts[4]
        rest = ':'.join(parts[5:])
        url = None
        if service == 'lambda':
            # arn:aws:lambda:region:acct:function:Name
            name = rest.split('function:')[-1]
            url = f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions/{name}"
        elif service == 'dynamodb':
            # arn:aws:dynamodb:region:acct:table/Name
            if 'table/' in rest:
                name = rest.split('table/')[-1].split('/')[0]
                url = f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#table?name={name}"
        elif service == 'cloudfront':
            # global console; use distribution id if present
            if '/distribution/' in arn:
                did = arn.split('/distribution/')[-1]
                url = f"https://console.aws.amazon.com/cloudfront/v3/home#/distributions/{did}"
        if url:
            return RedirectResponse(url=url, status_code=302)
        return JSONResponse({"error": "unsupported arn for console deeplink"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": f"console deeplink failed: {e}"}, status_code=500)
