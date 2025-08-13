from __future__ import annotations

import os
import time
import uuid
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus, urlparse, parse_qsl, urlencode, urlunparse
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

import boto3
from botocore.config import Config
from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
import orjson

from .graph import Graph
from .findings import analyze as analyze_findings

# ---- Enumerators (unchanged) ----
from .enumerators import (
    ec2, elbv2, lambda_ as enum_lambda, apigwv2, s3, sqs_sns,
    dynamodb, rds, eks, ecs, eventbridge, cloudfront,
    cloudwatchlogs, kms, cloudtrail, configservice, guardduty, flowlogs, ecr, wafv2
)


try:
    from .reachability import derive_reachability
except Exception:
    def derive_reachability(g: Graph):
        return []

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log = logging.getLogger("awsenum")
if not log.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-southeast-1")

# Performance knobs (env overridable)
FAST_ENUM = os.environ.get("FAST_ENUM", "1") not in ("0", "false", "False")
BOTO_MAX_ATTEMPTS = int(os.environ.get("BOTO_MAX_ATTEMPTS", "3"))
BOTO_READ_TIMEOUT = int(os.environ.get("BOTO_READ_TIMEOUT", "6"))
BOTO_CONNECT_TIMEOUT = int(os.environ.get("BOTO_CONNECT_TIMEOUT", "5"))
SERVICE_TIMEOUT_SEC = int(os.environ.get("SERVICE_TIMEOUT_SEC", "25"))         # hard cap per service
AWSENUM_WORKERS = int(os.environ.get("AWSENUM_WORKERS", "5"))                  # parallel services per region

def json_response(obj: Any) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(obj)))

def _boto_cfg(tag="awsenumv4") -> Config:
    return Config(
        retries={'max_attempts': max(1, BOTO_MAX_ATTEMPTS), 'mode': 'standard'},
        read_timeout=BOTO_READ_TIMEOUT,
        connect_timeout=BOTO_CONNECT_TIMEOUT,
        user_agent_extra=tag,
    )

def _short_cfg() -> Config:
    return _boto_cfg("awsenumv4/fast")

def build_session(ak: Optional[str], sk: Optional[str], st: Optional[str], region: str) -> boto3.Session:
    if ak and sk:
        return boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=st,
            region_name=region,
        )
    return boto3.Session(region_name=region)

def _id_last(data_id: str) -> str:
    return (data_id or '').split(':')[-1]

# -----------------------------------------------------------------------------
# App + UI
# -----------------------------------------------------------------------------
app = FastAPI()
app.mount('/ui', StaticFiles(directory=os.path.join(os.path.dirname(__file__), 'ui')), name='ui')

@app.get('/', response_class=HTMLResponse)
async def index():
    with open(os.path.join(os.path.dirname(__file__), 'ui', 'index.html'), 'r', encoding='utf-8') as f:
        return HTMLResponse(f.read())

# -----------------------------------------------------------------------------
# Progress tracking
# -----------------------------------------------------------------------------
_PROGRESS: Dict[str, Dict[str, Any]] = {}
_PROGRESS_LOCK = Lock()

def _p_init(rid: str, total: int, region: str) -> None:
    with _PROGRESS_LOCK:
        _PROGRESS[rid] = {"rid": rid, "total": max(1, int(total)), "current": 0,
                          "stage": f"Initializing ({region})", "done": False}

def _p_add_total(rid: str, delta: int) -> None:
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["total"] = max(1, int(_PROGRESS[rid]["total"]) + int(delta))

def _p_stage(rid: str, stage: str) -> None:
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            _PROGRESS[rid]["stage"] = stage

def _p_tick(rid: str, stage: Optional[str] = None) -> None:
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            p = _PROGRESS[rid]
            p["current"] = min(p["total"], p["current"] + 1)
            if stage:
                p["stage"] = stage

def _p_done(rid: str, stage: Optional[str] = None) -> None:
    with _PROGRESS_LOCK:
        if rid in _PROGRESS:
            p = _PROGRESS[rid]
            p["current"] = p["total"]
            p["done"] = True
            if stage:
                p["stage"] = stage

@app.get('/progress')
async def progress_api(rid: str = Query(...)):
    with _PROGRESS_LOCK:
        st = _PROGRESS.get(rid)
        if not st:
            return json_response({"rid": rid, "total": 1, "current": 0, "stage": "Unknown", "done": False})
        return json_response(st)

# -----------------------------------------------------------------------------
# Download endpoints (original) + S3 config (unchanged)
# -----------------------------------------------------------------------------
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
        return JSONResponse({"error": "functionArn or functionName required"}, status_code=400)
    try:
        meta = lam.get_function(FunctionName=fn)
        loc = (meta.get("Code") or {}).get("Location")
        if not loc:
            return JSONResponse({"error": "No code location available"}, status_code=404)
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
    sess = build_session(ak, sk, st, region)
    lam = sess.client('lambda', region_name=region, config=_boto_cfg())
    try:
        out = lam.get_layer_version(LayerName=layerArn, VersionNumber=int(version))
        loc = (out.get("Content") or {}).get("Location")
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
    sess = build_session(ak, sk, st, region)
    agw = sess.client('apigatewayv2', region_name=region, config=_boto_cfg())
    bundle: Dict[str, Any] = {}
    try:
        bundle['api'] = agw.get_api(ApiId=apiId)
        routes: List[Dict[str, Any]] = []; token = None
        while True:
            kw = {"ApiId": apiId}
            if token: kw["NextToken"] = token
            resp = agw.get_routes(**kw)
            routes.extend(resp.get("Items", []))
            token = resp.get("NextToken")
            if not token: break
        bundle['routes'] = routes
        integrations: List[Dict[str, Any]] = []; token = None
        while True:
            kw = {"ApiId": apiId}
            if token: kw["NextToken"] = token
            resp = agw.get_integrations(**kw)
            integrations.extend(resp.get("Items", []))
            token = resp.get("NextToken")
            if not token: break
        bundle['integrations'] = integrations
        stages = agw.get_stages(ApiId=apiId).get("Items", [])
        bundle['stages'] = stages
        data = orjson.dumps(bundle)
        filename = f"apigwv2-{apiId}.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
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
    sess = build_session(ak, sk, st, region)
    ddb = sess.client('dynamodb', region_name=region, config=_boto_cfg())
    try:
        name = tableName
        if not name and tableArn:
            if ":table/" in tableArn:
                name = tableArn.split(":table/")[-1].split("/")[0]
            elif ":table:" in tableArn:
                name = tableArn.split(":table:")[-1].split("/")[0]
        if not name:
            return JSONResponse({"error": "could not parse table name"}, status_code=400)
        desc = ddb.describe_table(TableName=name)
        data = orjson.dumps(desc)
        filename = f"dynamodb-{name}.json"
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
    sess = build_session(ak, sk, st, "us-east-1")
    cf = sess.client('cloudfront', config=_boto_cfg())
    try:
        out = cf.get_distribution_config(Id=id)
        data = orjson.dumps(out)
        filename = f"cloudfront-{id}-config.json"
        return Response(content=data, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})
    except Exception as e:
        return JSONResponse({"error": f"cloudfront get_distribution_config failed: {e}"}, status_code=500)

# S3 bucket configuration bundle (already added earlier)
@app.get('/download/s3-config')
async def download_s3_bucket_config(
    region: Optional[str] = Query(None),
    bucket: str = Query(...),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    try:
        sess = build_session(ak, sk, st, region or DEFAULT_REGION)
        s3c = sess.client('s3', region_name=region or DEFAULT_REGION, config=_boto_cfg())

        def _safe_call(fn, *args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as e:
                return {"__error__": str(e)}

        loc_resp = _safe_call(s3c.get_bucket_location, Bucket=bucket)
        bucket_region = None
        if isinstance(loc_resp, dict):
            lc = loc_resp.get('LocationConstraint')
            bucket_region = 'us-east-1' if lc in (None, '') else ('eu-west-1' if lc == 'EU' else lc)
        if bucket_region and (region or DEFAULT_REGION) != bucket_region:
            s3c = sess.client('s3', region_name=bucket_region, config=_boto_cfg())

        results: Dict[str, Any] = {"bucket": bucket, "region_hint": region, "resolved_region": bucket_region or (region or DEFAULT_REGION)}
        calls = {
            "policy": lambda: s3c.get_bucket_policy(Bucket=bucket),
            "policy_status": lambda: s3c.get_bucket_policy_status(Bucket=bucket),
            "public_access_block": lambda: s3c.get_public_access_block(Bucket=bucket),
            "encryption": lambda: s3c.get_bucket_encryption(Bucket=bucket),
            "acl": lambda: s3c.get_bucket_acl(Bucket=bucket),
            "cors": lambda: s3c.get_bucket_cors(Bucket=bucket),
            "website": lambda: s3c.get_bucket_website(Bucket=bucket),
            "logging": lambda: s3c.get_bucket_logging(Bucket=bucket),
            "versioning": lambda: s3c.get_bucket_versioning(Bucket=bucket),
            "tagging": lambda: s3c.get_bucket_tagging(Bucket=bucket),
            "lifecycle": lambda: s3c.get_bucket_lifecycle_configuration(Bucket=bucket),
        }
        errors: Dict[str, str] = {}
        for key, fn in calls.items():
            resp = _safe_call(fn)
            if isinstance(resp, dict) and '__error__' in resp:
                errors[key] = resp['__error__']
            else:
                results[key] = resp
        if errors: results["errors"] = errors

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
            url = f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#table?name={quote_plus(name)}"
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

# -----------------------------------------------------------------------------
# Enumerate orchestration (PARALLEL + TIMEOUT, findings preserved)
# -----------------------------------------------------------------------------
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
    ('cloudwatchlogs', cloudwatchlogs.enumerate),
    ('kms', kms.enumerate),
    ('cloudtrail', cloudtrail.enumerate),
    ('config', configservice.enumerate),
    ('guardduty', guardduty.enumerate),
    ('flowlogs', flowlogs.enumerate),
    ('ecr', ecr.enumerate),
    ('wafv2', wafv2.enumerate),
]

def _apply_short_timeouts_to_enumerators():
    cfg = _short_cfg()
    for m in (ec2, elbv2, dynamodb, s3, sqs_sns, enum_lambda, apigwv2, eventbridge, cloudfront, rds, eks, ecs):
        try:
            if hasattr(m, "CFG"):
                setattr(m, "CFG", cfg)
        except Exception:
            pass

def _inject_creds_into_existing_links(elements: List[Dict[str, Any]], ak: Optional[str], sk: Optional[str], st: Optional[str]) -> None:
    if not ak and not sk and not st: return
    for el in elements:
        if not isinstance(el, dict) or el.get("group") != "nodes": continue
        details = (el.get("data") or {}).get("details") or {}
        links = details.get("links")
        if not isinstance(links, list): continue
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
            links.append({"title": title, "href": href, "download": download})

        arn = details.get("arn")
        if isinstance(arn, str) and arn:
            add("Open in AWS Console", f"/download/console?arn={quote_plus(arn)}")

        if ntype == "lambda":
            fn_arn = details.get("arn"); fn_name = details.get("name") or data.get("label")
            if fn_arn or fn_name:
                qs = f"region={quote_plus(region)}"
                if fn_arn: qs += f"&functionArn={quote_plus(fn_arn)}"
                if fn_name: qs += f"&functionName={quote_plus(fn_name)}"
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

        if ntype in ("s3_bucket", "s3"):
            bucket_name = (details.get("name") or data.get("label"))
            if bucket_name:
                qs = f"region={quote_plus(region)}&bucket={quote_plus(bucket_name)}"
                add("Download S3 bucket config (json)", f"/download/s3-config?{qs}")

        if ntype == "cloudfront":
            dist_id = details.get("id") or _id_last(data.get("id") or "")
            if dist_id:
                qs = f"id={quote_plus(dist_id)}"
                add("Download CloudFront distribution config (json)", f"/download/cloudfront-config?{qs}")

def _run_services_parallel(sess: boto3.Session, account_id: str, region: str, rid: Optional[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Run all enumerators in parallel with a hard timeout per service.
    """
    g = Graph()
    warnings: List[str] = []
    tasks = []
    started_at: Dict[str, float] = {}

    def wrap(name, fn):
        def _call():
            started_at[name] = time.time()
            _p_stage(rid, f"{region}: {name}…")
            before = len(list(g.elements()))
            fn(sess, account_id, region, g, warnings)
            after = len(list(g.elements()))
            return name, max(0, after - before)
        return _call

    with ThreadPoolExecutor(max_workers=max(1, AWSENUM_WORKERS)) as ex:
        future_to_name = {}
        for name, fn in SERVICES_ORDER:
            fut = ex.submit(wrap(name, fn))
            future_to_name[fut] = name

        for fut in as_completed(future_to_name, timeout=None):
            name = future_to_name[fut]
            try:
                # Enforce per-service timeout when retrieving the result
                svc_name, added = fut.result(timeout=max(1, SERVICE_TIMEOUT_SEC))
                took = time.time() - started_at.get(name, time.time())
                _p_tick(rid, f"{region}: {svc_name} ({took:.1f}s) ✓")
                log.info("[%s] %s completed in %.1fs (+%d elements)", region, svc_name, took, added)
            except TimeoutError:
                warnings.append(f'{name} timed out after {SERVICE_TIMEOUT_SEC}s')
                _p_tick(rid, f"{region}: {name} timed out")
                log.warning("[%s] %s timed out after %ss", region, name, SERVICE_TIMEOUT_SEC)
            except Exception as e:
                warnings.append(f'{name} failed: {e}')
                _p_tick(rid, f"{region}: {name} failed")
                log.exception("[%s] %s failed: %s", region, name, e)

    return list(g.elements()), warnings

def _list_enabled_regions(sess: boto3.Session) -> List[str]:
    try:
        ec2c = sess.client('ec2', config=_boto_cfg())
        resp = ec2c.describe_regions(AllRegions=True)
        out = []
        for r in resp.get('Regions', []):
            if r.get('OptInStatus') in ('opt-in-not-required', 'opted-in'):
                out.append(r.get('RegionName'))
        return sorted(out)
    except Exception:
        return [DEFAULT_REGION]

# -----------------------------------------------------------------------------
# API
# -----------------------------------------------------------------------------
@app.post('/enumerate')
async def enumerate_api(req: Request):
    body = await req.json()
    ak = (body.get('access_key_id') or '').strip() or None
    sk = (body.get('secret_access_key') or '').strip() or None
    st = (body.get('session_token') or '').strip() or None
    region = (body.get('region') or DEFAULT_REGION).strip()
    scan_all = bool(body.get('scan_all'))
    rid = (body.get('rid') or '').strip() or str(uuid.uuid4())

    # Optional: reduce hanging
    if FAST_ENUM:
        _apply_short_timeouts_to_enumerators()

    _p_init(rid, total=len(SERVICES_ORDER) + 2, region=region)
    _p_stage(rid, f"Validating credentials ({region})")

    sess = build_session(ak, sk, st, region)

    # Validate creds fast
    try:
        sts = sess.client('sts', region_name=region, config=_boto_cfg())
        ident = sts.get_caller_identity()
        account_id = ident.get('Account') or '000000000000'
    except Exception as e:
        _p_done(rid, "Credential validation failed")
        return JSONResponse({"error": f"Credential validation failed: {e}"}, status_code=401)

    # Enumerate one region (parallel services)
    _p_stage(rid, f"Enumerating services ({region})")
    t0 = time.time()
    elements, warnings = await run_in_threadpool(_run_services_parallel, sess, account_id, region, rid)

    # Reachability + findings
    _p_stage(rid, f"{region}: reachability")
    gtmp = Graph()
    for el in elements:
        if el.get("group") == "nodes":
            d = el.get("data", {})
            gtmp.add_node(d.get("id"), d.get("label"), d.get("type"), d.get("region"), details=d.get("details"), parent=d.get("parent"), icon=d.get("icon"))
        else:
            d = el.get("data", {})
            gtmp.add_edge(d.get("id"), d.get("source"), d.get("target"), d.get("label"), d.get("type"), d.get("category"), details=d.get("details"))
    try:
        for e in derive_reachability(gtmp):
            gtmp.add_edge(**e)
    except Exception as e:
        warnings.append(f'derive_reachability failed: {e}')
    _p_tick(rid, f"{region}: reachability ✓")

    elements = list(gtmp.elements())

    _p_stage(rid, f"{region}: findings")
    findings = analyze_findings(elements)  # mutates elements (red edges/borders)
    _p_tick(rid, f"{region}: findings ✓")

    scanned_regions = [region]

    # (optional) scan-all
    if scan_all:
        extra_regions = [r for r in _list_enabled_regions(sess) if r != region]
        _p_add_total(rid, len(extra_regions) * (len(SERVICES_ORDER) + 2))
        for r in extra_regions:
            _p_stage(rid, f"Enumerating services ({r})")
            rsess = build_session(ak, sk, st, r)
            el2, w2 = await run_in_threadpool(_run_services_parallel, rsess, account_id, r, rid)
            warnings.extend(w2)
            # reachability + findings per region
            g2 = Graph()
            for el in el2:
                if el.get("group") == "nodes":
                    d = el.get("data", {})
                    g2.add_node(d.get("id"), d.get("label"), d.get("type"), d.get("region"), details=d.get("details"), parent=d.get("parent"), icon=d.get("icon"))
                else:
                    d = el.get("data", {})
                    g2.add_edge(d.get("id"), d.get("source"), d.get("target"), d.get("label"), d.get("type"), d.get("category"), details=d.get("details"))
            try:
                for e in derive_reachability(g2):
                    g2.add_edge(**e)
            except Exception as e:
                warnings.append(f'derive_reachability failed ({r}): {e}')
            _p_tick(rid, f"{r}: reachability ✓")

            el2 = list(g2.elements())
            _p_stage(rid, f"{r}: findings")
            f2 = analyze_findings(el2)
            _p_tick(rid, f"{r}: findings ✓")

            elements.extend(el2)
            for f in f2:
                # avoid dup finding objects
                if f not in findings:
                    findings.append(f)
            scanned_regions.append(r)

    # Credentialed downloads
    _inject_creds_into_existing_links(elements, ak, sk, st)
    _augment_download_links(elements, ak, sk, st)

    # Build findings_by_id for the UI
    findings_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        fid = f.get('id')
        if not fid: continue
        findings_by_id.setdefault(fid, []).append(f)

    took = time.time() - t0
    warnings.insert(0, f"Enumerated region {region} in {took:.1f}s; nodes={sum(1 for el in elements if el.get('group')=='nodes')}, edges={sum(1 for el in elements if el.get('group')=='edges')}")

    _p_done(rid, "Completed")

    return json_response({
        'rid': rid,
        'elements': elements,
        'warnings': warnings,
        'findings': findings,
        'findings_by_id': findings_by_id,
        'region': region,
        'scanned_regions': scanned_regions
    })
