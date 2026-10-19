import logging
import os
from datetime import datetime, timedelta, timezone
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
REGION = os.environ.get("REGION", "us-east-1")
CPU_THRESHOLD = float(os.environ.get("CPU_THRESHOLD", "5"))
MIN_AGE_DAYS = int(os.environ.get("MIN_AGE_DAYS", "7"))
SPOKE_ROLE_NAME = os.environ.get("SPOKE_ROLE_NAME", "SpokeSweeperRole")
SCAN_ORG = os.environ.get("SCAN_ORG", "false").lower() == "true"


def parse_tags(tags):
    return tags if isinstance(tags, dict) else {t["Key"]: t["Value"] for t in (tags or [])}


def is_protected(tags):
    td = parse_tags(tags)
    return td.get("FinOps:Action") == "Ignore" or td.get("Environment") == "Production"


def sweep_ebs(ec2, errors=None):
    findings, now = [], datetime.now(timezone.utc)
    for page in ec2.get_paginator("describe_volumes").paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page.get("Volumes", []):
            vol_id = vol["VolumeId"]
            try:
                if is_protected(vol.get("Tags", [])) or (now - vol["CreateTime"]) < timedelta(days=MIN_AGE_DAYS):
                    continue
                findings.append(vol_id)
                if DRY_RUN:
                    logger.info("DRY_RUN: Would snapshot and delete volume %s", vol_id)
                    continue
                filters = [{"Name": "volume-id", "Values": [vol_id]}, {"Name": "tag:AutomatedSweeper", "Values": ["True"]}]
                snaps = [s for p in ec2.get_paginator("describe_snapshots").paginate(Filters=filters) for s in p.get("Snapshots", [])]
                snap = snaps[0] if snaps else None
                if not snap:
                    snap = ec2.create_snapshot(
                        VolumeId=vol_id,
                        Description=f"Auto-snapshot by FinOps Sweeper for {vol_id}",
                        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "AutomatedSweeper", "Value": "True"}, {"Key": "SourceVolume", "Value": vol_id}]}],
                    )
                if ec2.describe_snapshots(SnapshotIds=[snap["SnapshotId"]])["Snapshots"][0]["State"] == "completed":
                    ec2.delete_volume(VolumeId=vol_id)
                    logger.info("Deleted volume %s", vol_id)
                else:
                    logger.info("Snapshot %s pending; skipped deleting %s", snap["SnapshotId"], vol_id)
            except Exception as e:
                logger.error("Error processing EBS volume %s: %s", vol_id, e)
                if errors is not None:
                    errors.append(f"ebs {vol_id}: {e}")
    return findings


def sweep_ec2(ec2, cw, errors=None):
    findings, now = [], datetime.now(timezone.utc)
    for page in ec2.get_paginator("describe_instances").paginate(Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                inst_id = inst["InstanceId"]
                try:
                    tags = inst.get("Tags", [])
                    if is_protected(tags) or "aws:autoscaling:groupName" in parse_tags(tags) or inst.get("RootDeviceType") != "ebs":
                        continue
                    # ponytail: CloudWatch CPU only, upgrade to CloudWatch Agent mem_used_percent for memory metrics
                    # ponytail: reactive threshold sweep, upgrade to predictive scaling policies for dynamic workloads
                    metrics = cw.get_metric_statistics(
                        Namespace="AWS/EC2", MetricName="CPUUtilization",
                        Dimensions=[{"Name": "InstanceId", "Value": inst_id}],
                        StartTime=now - timedelta(days=7), EndTime=now, Period=86400, Statistics=["Maximum"],
                    )
                    datapoints = metrics.get("Datapoints", [])
                    if not datapoints or max(dp["Maximum"] for dp in datapoints) >= CPU_THRESHOLD:
                        continue
                    findings.append(inst_id)
                    if DRY_RUN:
                        logger.info("DRY_RUN: Would stop instance %s", inst_id)
                        continue
                    ec2.stop_instances(InstanceIds=[inst_id])
                    ec2.create_tags(Resources=[inst_id], Tags=[{"Key": "StoppedBy", "Value": "FinOpsSweeper"}])
                    logger.info("Stopped idle instance %s", inst_id)
                except Exception as e:
                    logger.error("Error processing EC2 instance %s: %s", inst_id, e)
                    if errors is not None:
                        errors.append(f"ec2 {inst_id}: {e}")
    return findings


def sweep_eips(ec2, errors=None):
    findings = []
    # ponytail: unattached EIPs only, upgrade to VPC Flow Logs audit for zero-traffic public IPs
    for addr in ec2.describe_addresses().get("Addresses", []):
        res_id = addr.get("AllocationId") or addr.get("PublicIp")
        try:
            if "AssociationId" in addr or is_protected(addr.get("Tags", [])):
                continue
            findings.append(res_id)
            if DRY_RUN:
                logger.info("DRY_RUN: Would release EIP %s", res_id)
                continue
            kwargs = {"AllocationId": res_id} if "AllocationId" in addr else {"PublicIp": res_id}
            ec2.release_address(**kwargs)
            logger.info("Released EIP %s", res_id)
        except Exception as e:
            logger.error("Error processing EIP %s: %s", res_id, e)
            if errors is not None:
                errors.append(f"eip {res_id}: {e}")
    return findings


def sweep_elbs(elbv2, errors=None):
    # ponytail: report-only ELBs, upgrade to automated delete_load_balancer after approval period
    findings = []
    for page in elbv2.get_paginator("describe_load_balancers").paginate():
        for lb in page.get("LoadBalancers", []):
            lb_arn = lb["LoadBalancerArn"]
            try:
                td = elbv2.describe_tags(ResourceArns=[lb_arn]).get("TagDescriptions", [])
                if is_protected(td[0].get("Tags", []) if td else []):
                    continue
                try:
                    tgs = [tg for p in elbv2.get_paginator("describe_target_groups").paginate(LoadBalancerArn=lb_arn) for tg in p.get("TargetGroups", [])]
                except Exception:
                    tgs = []
                all_empty, all_unused = True, True
                for tg in tgs:
                    health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"]).get("TargetHealthDescriptions", [])
                    if health:
                        all_empty = False
                        if any(h.get("TargetHealth", {}).get("State") != "unused" for h in health):
                            all_unused = False
                            break
                if not tgs or all_empty or all_unused:
                    findings.append(lb_arn)
                    logger.info("Reported orphaned load balancer: %s", lb_arn)
            except Exception as e:
                logger.error("Error processing load balancer %s: %s", lb_arn, e)
                if errors is not None:
                    errors.append(f"elb {lb_arn}: {e}")
    return findings


def scan(session, errors=None):
    # ponytail: single region, upgrade to describe_regions loop for multi-region
    if errors is None:
        errors = []
    ec2 = session.client("ec2", region_name=REGION)
    cw = session.client("cloudwatch", region_name=REGION)
    elbv2 = session.client("elbv2", region_name=REGION)
    return {"ebs": sweep_ebs(ec2, errors), "ec2": sweep_ec2(ec2, cw, errors), "eips": sweep_eips(ec2, errors), "elbs": sweep_elbs(elbv2, errors)}


def get_session(account_id):
    sts = boto3.client("sts", region_name=REGION)
    c = sts.assume_role(RoleArn=f"arn:aws:iam::{account_id}:role/{SPOKE_ROLE_NAME}", RoleSessionName="FinOpsSweeper")["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])


def lambda_handler(event, context):
    # ponytail: synchronous scan loop, upgrade to SQS fan-out when account count exceeds Lambda 15m timeout
    # ponytail: logger-only summary, upgrade to SNS topic publish for Slack/email alerts
    # ponytail: count-based findings, upgrade to ce:GetCostAndUsage for dollar savings calculation
    errors = []
    if not SCAN_ORG:
        account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
        summary = {"dry_run": DRY_RUN, "accounts_scanned": 1, "findings": scan(get_session(account_id), errors), "errors": errors}
    else:
        findings, scanned = {}, 0
        org = boto3.client("organizations", region_name=REGION)
        for page in org.get_paginator("list_accounts").paginate():
            for acct in page.get("Accounts", []):
                if acct.get("Status") == "ACTIVE":
                    aid = acct["Id"]
                    try:
                        findings[aid] = scan(get_session(aid), errors)
                        scanned += 1
                    except Exception as e:
                        logger.error("Failed to sweep account %s: %s", aid, e)
                        errors.append(f"account {aid}: {e}")
        summary = {"dry_run": DRY_RUN, "accounts_scanned": scanned, "findings": findings, "errors": errors}
    logger.info("Sweeper summary: %s", summary)
    return summary
