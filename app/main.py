from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urlparse, parse_qsl, urlencode, urlunparse
from threading import Lock

import boto3
from botocore.config import Config
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
import orjson

from .graph import Graph

# --------------------------
# Config / helpers
# --------------------------

DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-southeast-1")

def _boto_cfg() -> Config:
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
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    return cur

def _id_last(data_id: str) -> str:
    return (data_id or '').split(':')[-1]

app = FastAPI()
app.mount('/ui', StaticFiles(directory=os.path.join(os.path.dirname(__file__), 'ui')), name='ui')

@app.get('/', response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), 'ui', 'index.html'), 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())

# --------------------------
# Progress tracking
# --------------------------

_PROGRESS: Dict[str, Any] = {}
_PROGRESS_LOCK = Lock()

def _progress_start(rid: str, total: int, stage: str):
    with _PROGRESS_LOCK:
        _PROGRESS[rid] = {"rid": rid, "total": max(1, total), "current": 0, "stage": stage, "done": False}

def _progress_update(rid: str, current: int):
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["current"] = max(0, current)

def _progress_stage(rid: str, stage: str):
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["stage"] = stage

def _progress_tick(rid: str, stage: Optional[str] = None, inc: int = 1):
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["current"] = min(_PROGRESS[rid]["total"], _PROGRESS[rid]["current"] + inc)
            if stage:
                _PROGRESS[rid]["stage"] = stage

def _progress_finish(rid: str, stage: Optional[str] = None):
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["current"] = _PROGRESS[rid]["total"]
            _PROGRESS[rid]["done"] = True
            if stage:
                _PROGRESS[rid]["stage"] = stage

@app.get('/progress')
async def progress_api(rid: str = Query(...)):
    with _PROGRESS_LOCK:
        state = _PROGRESS.get(rid)
        if not state:
            return json_response({"rid": rid, "total": 1, "current": 0, "stage": "Unknown", "done": False})
        return json_response(state)

# --------------------------
# JSON helpers
# --------------------------

def json_response(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(data)), status_code=status_code)

# --------------------------
# Enumerators & orchestration
# --------------------------

from .enumerators import (
    ec2, elbv2, lambda_ as enum_lambda, apigwv2, s3, sqs_sns,
    dynamodb, rds, eks, ecs, eventbridge, cloudfront
)

try:
    from .reachability import derive_reachability
except Exception:
    def derive_reachability(g: Graph):
        return []

DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-southeast-1")

try:
    from .findings import analyze_findings
except Exception:
    def analyze_findings(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return []

SERVICES_ORDER: List[Tuple[str, Any]] = [
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

def _inject_creds_into_existing_links(elements: List[Dict[str, Any]], ak: Optional[str], sk: Optional[str], st: Optional[str]) -> None:
    for el in elements:
        if not isinstance(el, dict) or el.get("group") != "nodes": continue
        data = el.get("data") or {}
        details = data.get("details") or {}
        links = details.get("links") or []
        for link in links:
            href = link.get("href")
            if not isinstance(href, str) or not href.startswith("/download/"): continue
            if ("ak=" in href) or ("sk=" in href) or ("st=" in href): continue
            u = urlparse(href); q = dict(parse_qsl(u.query))
            if ak: q["ak"] = ak
            if sk: q["sk"] = sk
            if st: q["st"] = st
            link["href"] = urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))

def _augment_download_links(elements: List[Dict[str, Any]], ak: Optional[str], sk: Optional[str], st: Optional[str]) -> None:
    for el in elements:
        if not isinstance(el, dict) or el.get("group") != "nodes": continue
        data = el.get("data") or {}
        ntype = data.get("type")
        region = data.get("region") or DEFAULT_REGION
        details = data.setdefault("details", {})
        links = details.setdefault("links", [])

        def add(title: str, href: str, download: bool = True):
            if href.startswith("/download/"):
                if "?" in href:
                    href += f"&ak={quote_plus(ak or '')}&sk={quote_plus(sk or '')}"
                    if st: href += f"&st={quote_plus(st)}"
                else:
                    href += f"?ak={quote_plus(ak or '')}&sk={quote_plus(sk or '')}"
                    if st: href += f"&st={quote_plus(st)}"
            links.append({"title": title, "href": href, "download": bool(download)})

        if ntype == "lambda":
            fn_arn = details.get("arn") or data.get("label")
            if fn_arn:
                qs = f"region={quote_plus(region)}&functionArn={quote_plus(fn_arn)}"
                add("Download Lambda code (zip)", f"/download/lambda-code?{qs}")
        if ntype == "lambda_layer":
            layer_arn = details.get("arn") or data.get("label")
            version = details.get("version") or details.get("Version")
            if layer_arn and version:
                qs = f"region={quote_plus(region)}&layerArn={quote_plus(layer_arn)}&version={quote_plus(str(version))}"
                add("Download Lambda layer (zip)", f"/download/lambda-layer?{qs}")
        if ntype == "api_gw_v2":
            api_id = details.get("api_id") or _id_last(data.get("id") or "")
            if api_id:
                qs = f"region={quote_plus(region)}&apiId={quote_plus(api_id)}"
                add("Download API Gateway (HTTP/WebSocket) export (json)", f"/download/apigwv2-export?{qs}")
        if ntype == "dynamodb_table":
            tab_arn = details.get("arn"); tab_name = details.get("name") or data.get("label")
            if tab_arn or tab_name:
                qs = f"region={quote_plus(region)}"
                if tab_arn: qs += f"&tableArn={quote_plus(tab_arn)}"
                if tab_name: qs += f"&tableName={quote_plus(tab_name)}"
                add("Download DynamoDB table (describe json)", f"/download/dynamodb-table?{qs}")
        # NEW: S3 bucket config download link
        if ntype == "s3_bucket":
            bucket_name = details.get("name") or data.get("label")
            if bucket_name:
                qs = f"region={quote_plus(region)}&bucket={quote_plus(bucket_name)}"
                add("Download S3 bucket config (json)", f"/download/s3-config?{qs}")
        if ntype == "cloudfront":
            dist_id = details.get("id") or _id_last(data.get("id") or "")
            if dist_id:
                qs = f"id={quote_plus(dist_id)}"
                add("Download CloudFront distribution config (json)", f"/download/cloudfront-config?{qs}")

def _enumerate_one_region(sess: boto3.Session, account_id: str, region: str, progress_rid: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    warnings: List[str] = []; g = Graph()
    if progress_rid: _progress_stage(progress_rid, f"Enumerating services ({region})")
    service_counts: Dict[str, int] = {}
    for name, fn in SERVICES_ORDER:
        try:
            before = len(list(g.elements()))
            _progress_stage(progress_rid, f"{region}: {name}")
            fn(sess, account_id, region, g, warnings)
            after = len(list(g.elements()))
            service_counts[name] = max(0, after - before)
        except Exception as e:
            warnings.append(f'{name} failed: {e}')
        finally:
            _progress_tick(progress_rid, f"{region}: {name} ✓")

    try:
        _progress_stage(progress_rid, f"{region}: reachability")
        for e in derive_reachability(g): g.add_edge(**e)
        _progress_tick(progress_rid, f"{region}: reachability ✓")
    except Exception as e:
        warnings.append(f'reachability failed: {e}')

    elements = list(g.elements())

    try:
        _progress_stage(progress_rid, f"{region}: findings")
        findings = analyze_findings(elements)  # mutates elements (adds classes/severity)
        _progress_tick(progress_rid, f"{region}: findings ✓")
    except Exception as e:
        warnings.append(f'findings failed: {e}')
        findings = []

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
        out = []
        resp = ec2c.describe_regions(AllRegions=True)
        for r in resp.get('Regions', []):
            if r.get('OptInStatus') in ('opt-in-not-required', 'opted-in'):
                out.append(r.get('RegionName'))
        return sorted(out)
    except Exception:
        return [DEFAULT_REGION]

@app.post('/enumerate')
async def enumerate_api(req: Request):
    body = await req.json()
    ak = (body.get('access_key_id') or '').strip()
    sk = (body.get('secret_access_key') or '').strip()
    st = (body.get('session_token') or '').strip() or None
    start_region = (body.get('region') or DEFAULT_REGION).strip()
    rid = (body.get('rid') or str(uuid.uuid4())).strip()
    scan_all: bool = bool(body.get('scan_all') or False)

    if not ak or not sk:
        return json_response({"error": "Missing access_key_id or secret_access_key"}, status_code=400)

    sess = build_session(ak, sk, st, start_region)

    # validate creds
    try:
        sts = sess.client('sts', region_name=start_region, config=_boto_cfg())
        ident = sts.get_caller_identity()
        account_id = ident.get('Account') or '000000000000'
    except Exception as e:
        return json_response({"error": f"Credential validation failed: {e}"}, status_code=401)

    _progress_start(rid, total=100, stage="Preparing")
    try:
        if scan_all:
            regions = _list_enabled_regions(sess)
        else:
            regions = [start_region]

        _progress_stage(rid, "Enumerating")
        scanned_regions: List[str] = []
        all_elements: List[Dict[str, Any]] = []
        all_warnings: List[str] = []
        all_findings: List[Dict[str, Any]] = []

        # split progress roughly into equal parts per region
        per_region = max(1, int(80 / max(1, len(regions))))
        current = 10
        _progress_update(rid, current)

        for r in regions:
            _progress_stage(rid, f"Enumerating {r}")
            elements, warnings, findings = await run_in_threadpool(_enumerate_one_region, sess, account_id, r, rid)
            all_elements.extend(elements)
            all_warnings.extend(warnings)
            all_findings.extend(findings)
            scanned_regions.append(r)
            current = min(90, current + per_region)
            _progress_update(rid, current)

        # credentialed downloads
        _inject_creds_into_existing_links(all_elements, ak, sk, st)
        _augment_download_links(all_elements, ak, sk, st)

        _progress_finish(rid, "Completed")
        return json_response({
            "rid": rid,
            "region": start_region,
            "scanned_regions": scanned_regions,
            "elements": all_elements,
            "warnings": all_warnings,
            "findings": all_findings,
        })
    except Exception as e:
        _progress_finish(rid, "Failed")
        return json_response({"error": f"Enumeration failed: {e}"}, status_code=500)

# --------------------------
# Download endpoints (unchanged + S3 config)
# --------------------------

@app.get('/download/lambda-code')
async def download_lambda_code(
    region: str = Query(...),
    functionArn: Optional[str] = Query(None),
    functionName: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = build_session(ak, sk, st, region)
    lam = sess.client('lambda', region_name=region, config=_boto_cfg())
    fn = functionArn or functionName
    if not fn:
        return JSONResponse({"error": "functionArn or functionName is required"}, status_code=400)
    try:
        info = lam.get_function(FunctionName=fn)
        code = info.get('Code', {}).get('Location')
        if not code:
            return JSONResponse({"error": "No code location returned"}, status_code=404)
        # stream redirect to S3 signed URL
        return RedirectResponse(url=code, status_code=307)
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
    sess = build_session(ak, sk, st, region)
    lam = sess.client('lambda', region_name=region, config=_boto_cfg())
    try:
        res = lam.get_layer_version(Arn=layerArn, VersionNumber=int(version))
        loc = res.get('Content', {}).get('Location')
        if not loc:
            return JSONResponse({"error": "No layer content location returned"}, status_code=404)
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
    sess = build_session(ak, sk, st, region)
    apigw = sess.client('apigatewayv2', region_name=region, config=_boto_cfg())
    try:
        res = apigw.get_api(ApiId=apiId)
        data = orjson.dumps(res)
        filename = f"apigwv2-{apiId}-export.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except Exception as e:
        return JSONResponse({"error": f"apigwv2 get_api failed: {e}"}, status_code=500)

@app.get('/download/dynamodb-table')
async def download_dynamodb_table(
    region: str = Query(...),
    tableArn: Optional[str] = Query(None),
    tableName: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = build_session(ak, sk, st, region)
    ddb = sess.client('dynamodb', region_name=region, config=_boto_cfg())
    if not tableArn and not tableName:
        return JSONResponse({"error": "tableArn or tableName is required"}, status_code=400)
    try:
        if tableArn:
            desc = ddb.describe_table(TableName=_id_last(tableArn)).get('Table')
        else:
            desc = ddb.describe_table(TableName=tableName).get('Table')
        data = orjson.dumps({"DescribeTable": desc})
        filename = f"dynamodb-{(tableName or _id_last(tableArn or ''))}-describe.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except Exception as e:
        return JSONResponse({"error": f"dynamodb describe_table failed: {e}"}, status_code=500)

@app.get('/download/cloudfront-config')
async def download_cloudfront_config(
    id: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    # CloudFront is a global service (us-east-1)
    region = 'us-east-1'
    sess = build_session(ak, sk, st, region)
    cf = sess.client('cloudfront', region_name=region, config=_boto_cfg())
    try:
        res = cf.get_distribution_config(Id=id)
        data = orjson.dumps(res)
        filename = f"cloudfront-{id}-config.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except Exception as e:
        return JSONResponse({"error": f"cloudfront get_distribution_config failed: {e}"}, status_code=500)

# NEW: S3 bucket configuration bundle
@app.get('/download/s3-config')
async def download_s3_bucket_config(
    region: Optional[str] = Query(None),
    bucket: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    """Bundle key S3 bucket configuration APIs into one JSON.
    Best-effort: missing permissions or absent sub-configs are recorded under `errors`.
    """
    try:
        sess = build_session(ak, sk, st, region or DEFAULT_REGION)
        # Initial client; S3 is global but some APIs behave better when targeting the bucket's region.
        s3 = sess.client('s3', region_name=region or DEFAULT_REGION, config=_boto_cfg())

        def _safe_call(fn, *args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                return {"__error__": str(e)}

        # Discover actual bucket region
        loc_resp = _safe_call(s3.get_bucket_location, Bucket=bucket)
        bucket_region = None
        if isinstance(loc_resp, dict):
            lc = loc_resp.get('LocationConstraint')
            if lc in (None, ''):
                bucket_region = 'us-east-1'
            elif lc == 'EU':  # legacy alias for eu-west-1
                bucket_region = 'eu-west-1'
            else:
                bucket_region = lc

        if bucket_region and (region or DEFAULT_REGION) != bucket_region:
            # Recreate client in the bucket's home region
            s3 = sess.client('s3', region_name=bucket_region, config=_boto_cfg())

        results: Dict[str, Any] = {
            "bucket": bucket,
            "region_hint": region,
            "resolved_region": bucket_region or (region or DEFAULT_REGION),
        }

        # Collect configs (best effort; errors captured)
        calls = {
            "policy": lambda: s3.get_bucket_policy(Bucket=bucket),
            "policy_status": lambda: s3.get_bucket_policy_status(Bucket=bucket),
            "public_access_block": lambda: s3.get_public_access_block(Bucket=bucket),
            "encryption": lambda: s3.get_bucket_encryption(Bucket=bucket),
            "acl": lambda: s3.get_bucket_acl(Bucket=bucket),
            "cors": lambda: s3.get_bucket_cors(Bucket=bucket),
            "website": lambda: s3.get_bucket_website(Bucket=bucket),
            "logging": lambda: s3.get_bucket_logging(Bucket=bucket),
            "versioning": lambda: s3.get_bucket_versioning(Bucket=bucket),
            "tagging": lambda: s3.get_bucket_tagging(Bucket=bucket),
            "lifecycle": lambda: s3.get_bucket_lifecycle_configuration(Bucket=bucket),
        }

        errors: Dict[str, str] = {}
        for key, fn in calls.items():
            resp = _safe_call(fn)
            if isinstance(resp, dict) and '__error__' in resp:
                errors[key] = resp['__error__']
            else:
                results[key] = resp

        if errors:
            results["errors"] = errors

        data = orjson.dumps(results)
        filename = f"s3-{bucket}-config.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except Exception as e:
        return JSONResponse({"error": f"s3 bucket config failed: {e}"}, status_code=500)

@app.get('/download/console')
async def open_in_console(arn: str = Query(...)):
    try:
        parts = arn.split(':')
        if len(parts) < 6:
            return JSONResponse({"error": "unsupported arn format"}, status_code=400)
        service = parts[2]; region = parts[3]
        rest = ':'.join(parts[5:])
        url = None
        if service == 'lambda':
            name = rest.split('function:')[-1]
            url = f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions/{quote_plus(name)}"
        elif service == 'dynamodb':
            name = rest.split('table/')[-1]
            url = f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#table?initialTagKey=&table={quote_plus(name)}"
        elif service == 'apigateway':
            api_id = rest.split('/apis/')[-1]
            url = f"https://{region}.console.aws.amazon.com/apigateway/main/apis/{quote_plus(api_id)}/routes"
        elif service == 'cloudfront':
            dist_id = _id_last(arn)
            url = f"https://{region}.console.aws.amazon.com/cloudfront/v3/home?region={region}#/distributions/{quote_plus(dist_id)}"
        elif service == 's3':
            name = rest.split(':::')[-1]
            url = f"https://s3.console.aws.amazon.com/s3/buckets/{quote_plus(name)}?region={region}&bucketType=general&tab=objects"
        if not url:
            return JSONResponse({"error": f"unsupported arn: {arn}"}, status_code=400)
        return RedirectResponse(url=url, status_code=307)
    except Exception as e:
        return JSONResponse({"error": f"console redirect failed: {e}"}, status_code=500)
