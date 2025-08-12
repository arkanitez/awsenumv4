from __future__ import annotations
from typing import List, Dict, Any, Optional

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from ..graph import Graph
from ..iam_edges import mk_id

# Enumerator-wide client config (main.py may monkey-patch this to speed things up)
CFG = BotoConfig(
    retries={'max_attempts': 8, 'mode': 'adaptive'},
    read_timeout=20,
    connect_timeout=10,
)

def _resolve_bucket_region(s3_client, name: str) -> Optional[str]:
    try:
        loc = s3_client.get_bucket_location(Bucket=name).get('LocationConstraint')
        if loc in (None, ''):
            return 'us-east-1'
        if loc == 'EU':  # legacy alias
            return 'eu-west-1'
        return loc
    except Exception:
        return None

def _acl_to_canned(acl_resp: Dict[str, Any]) -> str:
    try:
        grants = acl_resp.get('Grants', []) or []
        canned = 'private'
        for g in grants:
            gr = (g or {}).get('Grantee') or {}
            uri = gr.get('URI') or ''
            perm = (g or {}).get('Permission') or ''
            if uri.endswith('/AllUsers'):
                if perm in ('WRITE', 'WRITE_ACP', 'FULL_CONTROL'):
                    return 'public-read-write'
                if perm in ('READ',):
                    canned = 'public-read'
        return canned
    except Exception:
        return 'private'

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    """
    S3 enumeration that:
      - uses the bucket's home region for per-bucket APIs
      - normalizes details to match findings.py expectations
      - avoids bloated raw responses (e.g., ResponseMetadata)
    """
    # list_buckets is global
    s3_global = session.client('s3', config=CFG)
    try:
        res = s3_global.list_buckets()
    except ClientError as e:
        warnings.append(f's3 list_buckets: {e.response.get("Error", {}).get("Code")}')
        return

    for b in res.get('Buckets', []) or []:
        name = b.get('Name')
        if not name:
            continue

        # Region-sensitive calls must be made in the bucket's region
        loc = _resolve_bucket_region(s3_global, name) or region or 'us-east-1'
        s3 = session.client('s3', region_name=loc, config=CFG)

        details: Dict[str, Any] = {'name': name}

        # Policy status (+ boolean flag findings.py can read)
        try:
            pst = s3.get_bucket_policy_status(Bucket=name)
            ps = pst.get('PolicyStatus') or {}
            details['PolicyStatus'] = ps
            details['policy_allows_public'] = bool(ps.get('IsPublic'))
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucket', 'AccessDenied', 'NoSuchBucketPolicy'):
                warnings.append(f's3 get_bucket_policy_status({name}): {code}')

        # Bucket policy (optional) — store the policy string only
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            if isinstance(pol, dict) and 'Policy' in pol:
                details['Policy'] = pol['Policy']
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucketPolicy', 'NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_policy({name}): {code}')

        # Public Access Block — keep a single, normalized key
        try:
            pab = s3.get_public_access_block(Bucket=name)
            details['public_access_block'] = pab.get('PublicAccessBlockConfiguration') or {}
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchPublicAccessBlockConfiguration', 'NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_public_access_block({name}): {code}')

        # Default encryption — store ONLY the inner configuration (no ResponseMetadata)
        try:
            enc_resp = s3.get_bucket_encryption(Bucket=name)
            enc_conf = enc_resp.get('ServerSideEncryptionConfiguration') or {}
            if enc_conf:
                # Keep both keys pointing to the same minimal object for compatibility with findings.py
                details['ServerSideEncryptionConfiguration'] = enc_conf
                details['encryption'] = enc_conf
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            # Missing config is not an error; other codes are interesting
            if code not in ('ServerSideEncryptionConfigurationNotFoundError', 'NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_encryption({name}): {code}')

        # Versioning — normalize to include a simple "enabled" boolean
        try:
            ver = s3.get_bucket_versioning(Bucket=name) or {}
            enabled = (ver.get('Status') == 'Enabled')
            details['Versioning'] = {'Status': ver.get('Status'), 'enabled': enabled}
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_versioning({name}): {code}')

        # Server access logging — normalize to { Enabled: true, ... } or {}
        try:
            lg = s3.get_bucket_logging(Bucket=name) or {}
            if 'LoggingEnabled' in lg:
                details['Logging'] = {'Enabled': True, **(lg.get('LoggingEnabled') or {})}
            else:
                details['Logging'] = {}
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_logging({name}): {code}')

        # ACL — compress to canned value
        try:
            acl = s3.get_bucket_acl(Bucket=name) or {}
            details['acl'] = _acl_to_canned(acl)
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_acl({name}): {code}')

        # Optional extras (best effort, raw but small)
        for getter, key in (
            (s3.get_bucket_cors, 'CORS'),
            (s3.get_bucket_website, 'Website'),
            (s3.get_bucket_tagging, 'Tagging'),
            (s3.get_bucket_lifecycle_configuration, 'Lifecycle'),
        ):
            try:
                details[key] = getter(Bucket=name)
            except ClientError:
                pass

        # Add S3 node once with normalized details
        node_id = mk_id('s3', account_id, loc, name)
        g.add_node(node_id, name, 's3_bucket', loc, details=details)

        # Notification → Lambda edges
        try:
            notif = s3.get_bucket_notification_configuration(Bucket=name) or {}
            for cfg in notif.get('LambdaFunctionConfigurations', []) or []:
                lam_arn = cfg.get('LambdaFunctionArn')
                if lam_arn:
                    g.add_edge(
                        mk_id('edge', account_id, loc, 's3notif', name, lam_arn),
                        node_id,
                        mk_id('lambda', account_id, loc, lam_arn),
                        'event→lambda',
                        'trigger',
                        'data',
                        details={'source': 's3-notification'}
                    )
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            if code not in ('NoSuchBucket', 'AccessDenied'):
                warnings.append(f's3 get_bucket_notification_configuration({name}): {code}')
