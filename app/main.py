from __future__ import annotations

import os
import time
import uuid
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import boto3
from botocore.config import Config
from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
import orjson

from .graph import Graph
from .enumerators import (
    ec2,
    elbv2,
    lambda as enum_lambda,   # note: module is "lambda.py"
    apigwv2,
    s3,
    sqs_sns,
    dynamodb,
    rds,
    eks,
    ecs,
    eventbridge,
    cloudfront,
)

# Optional modules – keep app resilient if they're absent
try:
    from .reachability import derive_reachability  # type: ignore
except Exception:
    def derive_reachability(g: Graph):  # type: ignore
        return []

try:
    from .findings import analyze as analyze_findings  # type: ignore
except Exception:
    def analyze_findings(elements: List[Dict[str, Any]]) -> List[Dict[str, Any]]:  # type: ignore
        return []


DEFAULT_REGION = os.environ.get("DEFAULT_REGION", "ap-southeast-1")

def json_response(obj: Any) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(obj)))

def _boto_cfg() -> Config:
    return Config(
        retries={"max_attempts": 6, "mode": "adaptive"},
        user_agent_extra="awsenumv4",
    )

def build_session(ak: Optional[str], sk: Optional[str], st: Optional[str], region: str) -> boto3.Session:
    if ak and sk:
        return boto3.Session(
            aws_access_key_id=ak,
            aws_secret_access_key=sk,
            aws_session_token=st or None,
            region_name=region,
        )
    return boto3.Session(region_name=region)

def _safe_get(d: Dict[str, Any], *path: str) -> Optional[Any]:
    cur: Any = d
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur

def _id_last(data_id: str) -> str:
    return (data_id or "").split(":")[-1]


app = FastAPI()
app.mount(
    "/ui",
    StaticFiles(directory=os.path.join(os.path.dirname(__file__), "ui")),
    name="ui",
)

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(
        os.path.join(os.path.dirname(__file__), "ui", "index.html"),
        "r",
        encoding="utf-8",
    ) as f:
        return HTMLResponse(f.read())


# --------------------------
# In-memory session for creds (keyed by rid)
# --------------------------
_SESSIONS: Dict[str, Dict[str, Any]] = {}
_SESS_LOCK = Lock()
SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "1800"))  # 30 minutes

def _put_session(rid: str, ak: str, sk: str, st: Optional[str], region: str) -> None:
    with _SESS_LOCK:
        _SESSIONS[rid] = {"ak": ak, "sk": sk, "st": st, "region": region, "ts": time.time()}

def _get_session(rid: Optional[str]) -> Optional[Dict[str, Any]]:
    if not rid:
        return None
    with _SESS_LOCK:
        entry = _SESSIONS.get(rid)
        if not entry:
            return None
        if (time.time() - float(entry.get("ts", 0))) > SESSION_TTL_SECONDS:
            _SESSIONS.pop(rid, None)
            return None
        return entry

def _session_or_query_session(
    rid: Optional[str],
    ak: Optional[str],
    sk: Optional[str],
    st: Optional[str],
    region: Optional[str],
) -> boto3.Session:
    sess_entry = _get_session(rid)
    if sess_entry:
        return build_session(
            sess_entry["ak"],
            sess_entry["sk"],
            sess_entry.get("st"),
            region or sess_entry["region"] or DEFAULT_REGION,
        )
    return build_session(ak, sk, st, region or DEFAULT_REGION)


# --------------------------
# Progress tracking
# --------------------------
_PROGRESS: Dict[str, Dict[str, Any]] = {}
_PROGRESS_LOCK = Lock()

def _progress_init(rid: str, total: int, region: str) -> None:
    with _PROGRESS_LOCK:
        _PROGRESS[rid] = {
            "rid": rid,
            "total": max(1, int(total)),
            "current": 0,
            "stage": f"Initializing ({region})",
            "done": False,
            "regions": [region],
        }

def _progress_add_total(rid: str, delta: int) -> None:
    if not rid:
        return
    with _PROGRESS_LOCK:
        st = _PROGRESS.get(rid)
        if st:
            st["total"] = max(1, int(st.get("total", 1)) + int(delta))

def _progress_stage(rid: str, stage: str) -> None:
    if not rid:
        return
    with _PROGRESS_LOCK:
        st = _PROGRESS.get(rid)
        if st:
            st["stage"] = stage

def _progress_tick(rid: str, stage: Optional[str] = None) -> None:
    if not rid:
        return
    with _PROGRESS_LOCK:
        st = _PROGRESS.get(rid)
        if st:
            st["current"] = min(st.get("total", 1), st.get("current", 0) + 1)
            if stage:
                st["stage"] = stage

def _progress_done(rid: str) -> None:
    if not rid:
        return
    with _PROGRESS_LOCK:
        st = _PROGRESS.get(rid)
        if st:
            st["current"] = st.get("total", 1)
            st["stage"] = "Completed"
            st["done"] = True

@app.get("/progress")
async def progress_api(rid: str = Query(...)):
    with _PROGRESS_LOCK:
        state = _PROGRESS.get(rid)
        if not state:
            return json_response({"rid": rid, "total": 1, "current": 0, "stage": "Unknown", "done": False})
        return json_response(state)


# --------------------------
# Download endpoints (accept rid; use stored creds)
# --------------------------
@app.get("/download/lambda-code")
async def download_lambda_code(
    region: str = Query(...),
    functionArn: Optional[str] = Query(None),
    functionName: Optional[str] = Query(None),
    rid: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_or_query_session(rid, ak, sk, st, region)
    lam = sess.client("lambda", region_name=region, config=_boto_cfg())
    fn = functionArn or functionName
    if not fn:
        return JSONResponse({"error": "functionArn or functionName required"}, status_code=400)
    try:
        meta = lam.get_function(FunctionName=fn)
        loc = _safe_get(meta, "Code", "Location")
        if not loc:
            return JSONResponse({"error": "No code location available"}, status_code=404)
        return RedirectResponse(url=loc, status_code=307)
    except Exception as e:
        return JSONResponse({"error": f"lambda get_function failed: {e}"}, status_code=500)

@app.get("/download/lambda-layer")
async def download_lambda_layer(
    region: str = Query(...),
    layerArn: str = Query(...),
    version: str = Query(...),
    rid: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_or_query_session(rid, ak, sk, st, region)
    lam = sess.client("lambda", region_name=region, config=_boto_cfg())
    try:
        out = lam.get_layer_version(LayerName=layerArn, VersionNumber=int(version))
        loc = _safe_get(out, "Content", "Location")
        if not loc:
            return JSONResponse({"error": "No layer content location available"}, status_code=404)
        return RedirectResponse(url=loc, status_code=307)
    except Exception as e:
        return JSONResponse({"error": f"lambda get_layer_version failed: {e}"}, status_code=500)

@app.get("/download/apigwv2-export")
async def download_apigwv2_export(
    region: str = Query(...),
    apiId: str = Query(...),
    rid: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_or_query_session(rid, ak, sk, st, region)
    agw = sess.client("apigatewayv2", region_name=region, config=_boto_cfg())
    bundle: Dict[str, Any] = {}
    try:
        bundle["api"] = agw.get_api(ApiId=apiId)

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
        bundle["routes"] = routes

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
        bundle["integrations"] = integrations

        stages = agw.get_stages(ApiId=apiId).get("Items", [])
        bundle["stages"] = stages

        data = orjson.dumps(bundle)
        filename = f"apigwv2-{apiId}.json"
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return JSONResponse({"error": f"apigatewayv2 export failed: {e}"}, status_code=500)

@app.get("/download/dynamodb-table")
async def download_dynamodb_table(
    region: str = Query(...),
    tableArn: Optional[str] = Query(None),
    tableName: Optional[str] = Query(None),
    rid: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    if not tableArn and not tableName:
        return JSONResponse({"error": "tableArn or tableName required"}, status_code=400)

    sess = _session_or_query_session(rid, ak, sk, st, region)
    ddb = sess.client("dynamodb", region_name=region, config=_boto_cfg())

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
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return JSONResponse({"error": f"dynamodb describe_table failed: {e}"}, status_code=500)

@app.get("/download/cloudfront-config")
async def download_cloudfront_config(
    id: str = Query(...),
    rid: Optional[str] = Query(None),
    ak: Optional[str] = Query(None),
    sk: Optional[str] = Query(None),
    st: Optional[str] = Query(None),
):
    sess = _session_or_query_session(rid, ak, sk, st, "us-east-1")  # CloudFront control-plane
    cf = sess.client("cloudfront", config=_boto_cfg())
    try:
        out = cf.get_distribution_config(Id=id)
        data = orjson.dumps(out)
        filename = f"cloudfront-{id}-config.json"
        return Response(
            content=data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return JSONResponse({"error": f"cloudfront get_distribution_config failed: {e}"}, status_code=500)

@app.get("/download/console")
async def open_in_console(arn: str = Query(...)):
    try:
        parts = arn.split(":")
        if len(parts) < 6:
            return JSONResponse({"error": "unsupported arn format"}, status_code=400)
        service = parts[2]
        region = parts[3]
        rest = ":".join(parts[5:])
        url = None

        if service == "lambda":
            name = rest.split("function:")[-1]
            url = f"https://{region}.console.aws.amazon.com/lambda/home?region={region}#/functions/{name}"
        elif service == "dynamodb":
            if "table/" in rest:
                name = rest.split("table/")[-1].split("/")[0]
                url = f"https://{region}.console.aws.amazon.com/dynamodbv2/home?region={region}#table?name={name}"
        elif service == "cloudfront":
            if "/distribution/" in arn:
                did = arn.split("/distribution/")[-1]
                url = f"https://console.aws.amazon.com/cloudfront/v3/home#/distributions/{did}"

        if url:
            return RedirectResponse(url=url, status_code=302)
        return JSONResponse({"error": "unsupported arn for console deeplink"}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": f"console deeplink failed: {e}"}, status_code=500)


# --------------------------
# Enumeration (with progress)
# --------------------------
SERVICES_ORDER: List[Tuple[str, Any]] = [
    ("ec2", ec2.enumerate),
    ("elbv2", elbv2.enumerate),
    ("dynamodb", dynamodb.enumerate),
    ("s3", s3.enumerate),
    ("sqs_sns", sqs_sns.enumerate),
    ("lambda", enum_lambda.enumerate),
    ("apigwv2", apigwv2.enumerate),
    ("eventbridge", eventbridge.enumerate),
    ("cloudfront", cloudfront.enumerate),
    ("rds", rds.enumerate),
    ("eks", eks.enumerate),
    ("ecs", ecs.enumerate),
]

def _enumerate_one_region(
    sess: boto3.Session, account_id: str, region: str, progress_rid: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
    warnings: List[str] = []
    g = Graph()

    if progress_rid:
        _progress_stage(progress_rid, f"Enumerating services ({region})")

    service_counts: Dict[str, int] = {}
    for name, fn in SERVICES_ORDER:
        try:
            before = len(list(g.elements()))
            _progress_stage(progress_rid or "", f"{region}: {name}")
            fn(sess, account_id, region, g, warnings)
            after = len(list(g.elements()))
            service_counts[name] = max(0, after - before)
        except Exception as e:
            warnings.append(f"{name} failed: {e}")
        finally:
            _progress_tick(progress_rid or "", f"{region}: {name} ✓")

    try:
        _progress_stage(progress_rid or "", f"{region}: reachability")
        for e in derive_reachability(g):
            g.add_edge(**e)
    except Exception as e:
        warnings.append(f"derive_reachability failed: {e}")
    finally:
        _progress_tick(progress_rid or "", f"{region}: reachability ✓")

    elements: List[Dict[str, Any]] = list(g.elements())

    try:
        _progress_stage(progress_rid or "", f"{region}: findings")
        findings = analyze_findings(elements)
    except Exception:
        findings = []
    finally:
        _progress_tick(progress_rid or "", f"{region}: findings ✓")

    try:
        total_nodes = sum(1 for el in elements if "source" not in (el.get("data") or {}))
        total_edges = sum(1 for el in elements if "source" in (el.get("data") or {}))
        warnings.insert(
            0,
            f"Enumerated region {region}: nodes={total_nodes}, edges={total_edges}, per_service={service_counts}",
        )
    except Exception:
        warnings.insert(0, f"Enumerated region {region}: elements={len(elements)}")

    return elements, warnings, findings

def _list_enabled_regions(sess: boto3.Session) -> List[str]:
    try:
        ec2c = sess.client("ec2", config=_boto_cfg())
        out = ec2c.describe_regions(AllRegions=False)
        return sorted([r["RegionName"] for r in out.get("Regions", [])])
    except Exception:
        return [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-central-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
        ]

def _augment_download_links(elements: List[Dict[str, Any]], rid: Optional[str]) -> None:
    for el in elements:
        if not isinstance(el, dict) or el.get("group") != "nodes":
            continue

        data = el.get("data") or {}
        ntype = data.get("type")
        region = data.get("region") or DEFAULT_REGION
        details = data.setdefault("details", {})
        links = details.setdefault("links", [])

        def add(title: str, href: str, download: bool = True):
            if rid:
                href = f"{href}&rid={quote_plus(rid)}" if ("?" in href) else f"{href}?rid={quote_plus(rid)}"
            links.append({"title": title, "href": href, "download": download})

        arn = details.get("arn")
        if arn and isinstance(arn, str):
            add("Open in AWS Console", f"/download/console?arn={quote_plus(arn)}", download=False)

        if ntype == "lambda":
            fn_arn = details.get("arn")
            fn_name = details.get("name") or data.get("label")
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
            tab_arn = details.get("arn")
            tab_name = details.get("name") or data.get("label")
            if tab_arn or tab_name:
                qs = f"region={quote_plus(region)}"
                if tab_arn: qs += f"&tableArn={quote_plus(tab_arn)}"
                if tab_name: qs += f"&tableName={quote_plus(tab_name)}"
                add("Download DynamoDB table (describe json)", f"/download/dynamodb-table?{qs}")

        if ntype == "cloudfront":
            dist_id = details.get("id") or _id_last(data.get("id") or "")
            if dist_id:
                add("Download CloudFront distribution config (json)", f"/download/cloudfront-config?id={quote_plus(dist_id)}")


@app.post("/enumerate")
async def enumerate_api(req: Request):
    """
    Runs heavy boto3 enumeration in a threadpool so the event loop stays responsive for /progress.
    Also seeds a short-lived credential session keyed by 'rid' (used later by download endpoints).
    """
    # Tolerant body parsing (JSON is expected; fall back to form if needed)
    try:
        if (req.headers.get("content-type") or "").lower().startswith("application/json"):
            body = await req.json()
        else:
            form = await req.form()
            body = dict(form.items())
    except Exception:
        body = {}

    ak = (body.get("access_key_id") or "").strip()
    sk = (body.get("secret_access_key") or "").strip()
    st = (body.get("session_token") or None) or None
    rid = (body.get("rid") or "").strip() or str(uuid.uuid4())
    region = (body.get("region") or DEFAULT_REGION).strip() or DEFAULT_REGION

    if not ak or not sk:
        return JSONResponse({"error": "Both access_key_id and secret_access_key are required."}, status_code=400)

    _put_session(rid, ak, sk, st, region)
    _progress_init(rid, total=len(SERVICES_ORDER) + 3, region=region)

    def _do():
        sess = build_session(ak, sk, st, region)
        sts = sess.client("sts", config=_boto_cfg())
        acct = sts.get_caller_identity()["Account"]

        regions = _list_enabled_regions(sess)
        if regions and region not in regions:
            regions = [region] + regions
        add_total = (len(SERVICES_ORDER) + 3) * max(0, len(regions) - 1)
        _progress_add_total(rid, add_total)

        all_elements: List[Dict[str, Any]] = []
        all_warnings: List[str] = []
        all_findings: List[Dict[str, Any]] = []

        for r in regions:
            rsess = build_session(ak, sk, st, r)
            els, warns, finds = _enumerate_one_region(rsess, acct, r, progress_rid=rid)
            all_elements.extend(els)
            all_warnings.extend(warns)
            all_findings.extend(finds)

        _augment_download_links(all_elements, rid=rid)
        _progress_done(rid)
        return all_elements, all_warnings, all_findings

    try:
        # ★ FIX: await the threadpool helper (previous version returned the coroutine)
        elements, warnings, findings = await run_in_threadpool(_do)
        return json_response({"rid": rid, "elements": elements, "warnings": warnings, "findings": findings})
    except Exception as e:
        _progress_done(rid)
        return JSONResponse({"error": f"enumeration failed: {e}"}, status_code=500)
