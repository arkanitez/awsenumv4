from __future__ import annotations
from typing import List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from ..graph import Graph
from ..iam_edges import mk_id, add_edges_from_role_policies

CFG = BotoConfig(retries={'max_attempts': 8, 'mode': 'adaptive'}, read_timeout=20, connect_timeout=10)

def classify_target_type(s: str) -> str:
    if s.startswith('igw-'): return 'igw'
    if s.startswith('nat-'): return 'nat_gateway'
    if s.startswith('tgw-'): return 'tgw'
    if s.startswith('pcx-'): return 'pcx'
    if s.startswith('eni-'): return 'eni'
    if s.startswith('i-'): return 'instance'
    return 'target'

def range_to_str(f,t,proto) -> str:
    if proto in ('-1','all'): return 'all'
    if f is None and t is None: return 'all'
    if f == t: return str(f)
    return f"{f}-{t}"

def enumerate(session: boto3.Session, account_id: str, region: str, g: Graph, warnings: List[str]) -> None:
    ec2 = session.client('ec2', region_name=region, config=CFG)

    # VPCs
    try:
        for v in ec2.describe_vpcs().get('Vpcs', []):
            vid = v['VpcId']
            g.add_node(mk_id('vpc', account_id, region, vid), f"VPC {vid}", 'vpc', region, details={'cidr': v.get('CidrBlock')})
    except ClientError as e:
        warnings.append(f'ec2 describe_vpcs: {e.response["Error"]["Code"]}'); return

    # Subnets
    try:
        for s in ec2.describe_subnets().get('Subnets', []):
            sid = s['SubnetId']; vid = s['VpcId']
            g.add_node(mk_id('subnet', account_id, region, sid), f'Subnet {sid}', 'subnet', region,
                       details={'cidr': s.get('CidrBlock'), 'az': s.get('AvailabilityZone')},
                       parent=mk_id('vpc', account_id, region, vid))
    except ClientError as e:
        warnings.append(f'ec2 describe_subnets: {e.response["Error"]["Code"]}')

    # Route tables + routes
    try:
        for rt in ec2.describe_route_tables().get('RouteTables', []):
            rtid = rt['RouteTableId']; vpcid = rt.get('VpcId')
            g.add_node(mk_id('rtb', account_id, region, rtid), f'RTB {rtid}', 'route_table', region,
                       parent=mk_id('vpc', account_id, region, vpcid) if vpcid else None)
            for assoc in rt.get('Associations', []) or []:
                sid = assoc.get('SubnetId')
                if sid:
                    g.add_edge(mk_id('edge', account_id, region, sid, rtid),
                               mk_id('subnet', account_id, region, sid),
                               mk_id('rtb', account_id, region, rtid),
                               'assoc', 'assoc', 'resource')
            for r in rt.get('Routes', []) or []:
                dst = r.get('DestinationCidrBlock') or r.get('DestinationIpv6CidrBlock') or r.get('DestinationPrefixListId')
                target = r.get('GatewayId') or r.get('NatGatewayId') or r.get('TransitGatewayId') or r.get('VpcPeeringConnectionId') or r.get('InstanceId') or r.get('NetworkInterfaceId')
                if dst and target:
                    ttype = classify_target_type(str(target))
                    g.add_node(mk_id(ttype, account_id, region, target), str(target), ttype, region,
                               parent=mk_id('vpc', account_id, region, vpcid) if vpcid else None)
                    g.add_edge(mk_id('edge', account_id, region, rtid, target, str(dst)),
                               mk_id('rtb', account_id, region, rtid),
                               mk_id(ttype, account_id, region, target),
                               f'route→{dst}', 'route', 'network')
    except ClientError as e:
        warnings.append(f'ec2 describe_route_tables: {e.response["Error"]["Code"]}')

    # SGs + collapsed rules
    try:
        sgs = ec2.describe_security_groups().get('SecurityGroups', [])
        for sg in sgs:
            sgid = sg['GroupId']; vpcid = sg.get('VpcId')
            g.add_node(mk_id('sg', account_id, region, sgid), f"{sg.get('GroupName')} ({sgid})", 'security_group', region,
                       details={'desc': sg.get('Description')},
                       parent=mk_id('vpc', account_id, region, vpcid) if vpcid else None)
        def collapse(perms, direction: str, sgid: str):
            agg: Dict[str, Dict[str, set]] = {}
            for p in perms or []:
                proto = p.get('IpProtocol', 'all'); f = p.get('FromPort'); t = p.get('ToPort')
                pr = range_to_str(f, t, proto)
                for r in p.get('IpRanges', []):
                    cidr = r.get('CidrIp')
                    if cidr: agg.setdefault(cidr, {}).setdefault(proto, set()).add(pr)
                for up in p.get('UserIdGroupPairs', []):
                    other = up.get('GroupId')
                    if other: agg.setdefault(other, {}).setdefault(proto, set()).add(pr)
            for peer, protos in agg.items():
                label = '; '.join([f"{k}:{','.join(sorted(v))}" for k,v in protos.items()])
                src = mk_id('sg', account_id, region, peer) if str(peer).startswith('sg-') else mk_id('cidr', account_id, region, peer)
                typ = 'security_group' if str(peer).startswith('sg-') else 'cidr'
                g.add_node(src, str(peer), typ, region)
                tgt = mk_id('sg', account_id, region, sgid)
                a, b = (src, tgt) if direction=='ingress' else (tgt, src)
                g.add_edge(mk_id('edge', account_id, region, a, b, direction), a, b, label, 'sg-rule', 'network')
        for sg in sgs:
            sgid = sg['GroupId']
            collapse(sg.get('IpPermissions'), 'ingress', sgid)
            collapse(sg.get('IpPermissionsEgress'), 'egress', sgid)
    except ClientError as e:
        warnings.append(f'ec2 describe_security_groups: {e.response["Error"]["Code"]}')

    # ENIs + instances + instance role IAM edges
    iam = session.client('iam', config=CFG)
    try:
        # Instances for IAM profile & role
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for res in page.get('Reservations', []) or []:
                for inst in res.get('Instances', []) or []:
                    iid = inst['InstanceId']; vpcid = inst.get('VpcId'); sid = inst.get('SubnetId')
                    parent = mk_id('subnet', account_id, region, sid) if sid else (mk_id('vpc', account_id, region, vpcid) if vpcid else None)
                    g.add_node(mk_id('instance', account_id, region, iid), iid, 'instance', region, parent=parent)
                    prof = inst.get('IamInstanceProfile', {})
                    if prof and 'Arn' in prof:
                        # Instance profile -> roles
                        try:
                            prof_name = prof['Arn'].split('/')[-1]
                            ip = iam.get_instance_profile(InstanceProfileName=prof_name)['InstanceProfile']
                            for r in ip.get('Roles', []) or []:
                                role_arn = r.get('Arn')
                                if role_arn:
                                    from ..iam_edges import add_edges_from_role_policies
                                    add_edges_from_role_policies(session, role_arn,
                                        mk_id('instance', account_id, region, iid),
                                        iid, account_id, region, g, warnings)
                        except ClientError as e:
                            warnings.append(f'iam get_instance_profile: {e.response["Error"]["Code"]}')
    except ClientError: pass

    try:
        enis = ec2.describe_network_interfaces().get('NetworkInterfaces', [])
        for eni in enis:
            enid = eni['NetworkInterfaceId']; vpcid = eni.get('VpcId'); sid = eni.get('SubnetId')
            parent = mk_id('subnet', account_id, region, sid) if sid else (mk_id('vpc', account_id, region, vpcid) if vpcid else None)
            g.add_node(mk_id('eni', account_id, region, enid), enid, 'eni', region, details={'private_ip': eni.get('PrivateIpAddress')}, parent=parent)
            for sgid in [x['GroupId'] for x in eni.get('Groups', [])]:
                g.add_edge(mk_id('edge', account_id, region, enid, sgid),
                           mk_id('eni', account_id, region, enid),
                           mk_id('sg', account_id, region, sgid),
                           'has-sg', 'attach', 'resource')
            if eni.get('Attachment', {}).get('InstanceId'):
                iid = eni['Attachment']['InstanceId']
                g.add_node(mk_id('instance', account_id, region, iid), iid, 'instance', region, parent=parent)
                g.add_edge(mk_id('edge', account_id, region, iid, enid),
                           mk_id('instance', account_id, region, iid),
                           mk_id('eni', account_id, region, enid),
                           'eni', 'attach', 'resource')
    except ClientError:
        pass
