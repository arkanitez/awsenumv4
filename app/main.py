from __future__ import annotations

import os
import time
import uuid
import logging
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
from .findings import analyze as analyze_findings  # findings engine

from .enumerators import (
    ec2, elbv2, lambda_ as enum_lambda, apigwv2, s3, sqs_sns,
    dynamodb, rds, eks, ecs, eventbridge, cloudfront
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

# Optional knobs to keep enumeration from feeling "stuck"
FAST_ENUM = os.environ.get("FAST_ENUM", "1") not in ("0", "false", "False")
BOTO_MAX_ATTEMPTS = int(os.environ.get("BOTO_MAX_ATTEMPTS", "3"))
BOTO_READ_TIMEOUT = int(os.environ.get("BOTO_READ_TIMEOUT", "6"))
BOTO_CONNECT_TIMEOUT = int(os.environ.get("BOTO_CONNECT_TIMEOUT", "5"))

def json_response(obj: Any) -> JSONResponse:
    return JSONResponse(orjson.loads(orjson.dumps(obj)))

def _boto_cfg() -> Config:
    # Keep our own helper calls snappy too
    return Config(
        retries={'max_attempts': max(1, BOTO_MAX_ATTEMPTS), 'mode': 'standard'},
        read_timeout=BOTO_READ_TIMEOUT,
        connect_timeout=BOTO_CONNECT_TIMEOUT,
        user_agent_extra='awsenumv4',
    )

def _short_cfg() -> Config:
    # What we push into each enumerator module's CFG
    return Config(
        retries={'max_attempts': max(1, BOTO_MAX_ATTEMPTS), 'mode': 'standard'},
        read_timeout=BOTO_READ_TIMEOUT,
        connect_timeout=BOTO_CONNECT_TIMEOUT,
        user_agent_extra='awsenumv4/fast',
    )

def build_session(ak: Optional[str], sk: Optional[str], st: Optional[str], region: str) -> boto3.Session:
    if a
