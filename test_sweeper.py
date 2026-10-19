import datetime
import pytest
import boto3
from moto import mock_aws
from moto.ec2 import ec2_backends
from moto.core import DEFAULT_ACCOUNT_ID
import sweeper


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


def make_aged_volume(ec2, days=10, **kwargs):
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, **kwargs)
    backend = ec2_backends[DEFAULT_ACCOUNT_ID]["us-east-1"]
    v_obj = backend.get_volume(vol["VolumeId"])
    old_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    v_obj.create_time = old_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return vol["VolumeId"]


@mock_aws
def test_ebs_available_volume_found():
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(ec2, days=10)
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id in findings


@mock_aws
def test_ebs_attached_volume_ignored():
    ec2 = boto3.client("ec2", "us-east-1")
    inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
    vol_id = make_aged_volume(ec2, days=10)
    ec2.attach_volume(VolumeId=vol_id, InstanceId=inst["InstanceId"], Device="/dev/sdf")
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id not in findings


@mock_aws
def test_ebs_ignore_tag_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(
        ec2,
        days=10,
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "FinOps:Action", "Value": "Ignore"}],
        }],
    )
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id not in findings


@mock_aws
def test_ebs_production_tag_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(
        ec2,
        days=10,
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "Environment", "Value": "Production"}],
        }],
    )
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id not in findings


@mock_aws
def test_ebs_younger_than_min_age_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    # Fresh volume has age 0 days < MIN_AGE_DAYS (7)
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=1)
    findings = sweeper.sweep_ebs(ec2)
    assert vol["VolumeId"] not in findings


@mock_aws
def test_ebs_dry_run_deletes_nothing_and_creates_no_snapshot(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", True)
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(ec2, days=10)
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id in findings
    # Verify volume still exists
    vols = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"]
    assert len(vols) == 1
    # Verify no snapshots created
    snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [vol_id]}])["Snapshots"]
    assert len(snaps) == 0


@mock_aws
def test_ebs_real_run_creates_snapshot_and_deletes_volume(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(ec2, days=10)
    findings = sweeper.sweep_ebs(ec2)
    assert vol_id in findings
    # Verify snapshot created and tagged
    snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [vol_id]}])["Snapshots"]
    assert len(snaps) == 1
    tags = {t["Key"]: t["Value"] for t in snaps[0].get("Tags", [])}
    assert tags.get("AutomatedSweeper") == "True"
    assert tags.get("SourceVolume") == vol_id
    # Verify volume deleted
    vols = ec2.describe_volumes()["Volumes"]
    assert not any(v["VolumeId"] == vol_id for v in vols)


@mock_aws
def test_ebs_second_run_does_not_create_second_snapshot(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    vol_id = make_aged_volume(ec2, days=10)
    # First snapshot created manually in pending state
    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [
                {"Key": "AutomatedSweeper", "Value": "True"},
                {"Key": "SourceVolume", "Value": vol_id},
            ],
        }],
    )
    backend = ec2_backends[DEFAULT_ACCOUNT_ID]["us-east-1"]
    backend.get_snapshot(snap["SnapshotId"]).status = "pending"

    # First run finds existing pending snapshot, does not create another, does not delete
    sweeper.sweep_ebs(ec2)
    snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [vol_id]}])["Snapshots"]
    assert len(snaps) == 1
    assert len(ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"]) == 1

    # Transition snapshot to completed
    backend.get_snapshot(snap["SnapshotId"]).status = "completed"
    # Second run sees completed snapshot, deletes volume, does not create second snapshot
    sweeper.sweep_ebs(ec2)
    snaps = ec2.describe_snapshots(Filters=[{"Name": "volume-id", "Values": [vol_id]}])["Snapshots"]
    assert len(snaps) == 1
    assert not any(v["VolumeId"] == vol_id for v in ec2.describe_volumes()["Volumes"])


def create_ec2_with_cpu(ec2, cw, cpu_val, tags=None):
    inst = ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags}] if tags else [],
    )["Instances"][0]
    inst_id = inst["InstanceId"]
    if cpu_val is not None:
        now = datetime.datetime.now(datetime.timezone.utc)
        cw.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[{
                "MetricName": "CPUUtilization",
                "Dimensions": [{"Name": "InstanceId", "Value": inst_id}],
                "Timestamp": now - datetime.timedelta(days=1),
                "Value": cpu_val,
                "Unit": "Percent",
            }],
        )
    return inst_id


@mock_aws
def test_ec2_idle_instance_found():
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 2.0)
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id in findings


@mock_aws
def test_ec2_busy_instance_left_alone():
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 25.0)
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id not in findings


@mock_aws
def test_ec2_no_datapoints_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, None)
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id not in findings


@mock_aws
def test_ec2_ignore_tag_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 1.0, tags=[{"Key": "FinOps:Action", "Value": "Ignore"}])
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id not in findings


@mock_aws
def test_ec2_autoscaling_tagged_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 1.0, tags=[{"Key": "aws:autoscaling:groupName", "Value": "prod-asg"}])
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id not in findings


@mock_aws
def test_ec2_dry_run_changes_nothing(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", True)
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 1.5)
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id in findings
    desc = ec2.describe_instances(InstanceIds=[inst_id])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] == "running"
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert "StoppedBy" not in tags


@mock_aws
def test_ec2_real_run_stops_and_tags(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    cw = boto3.client("cloudwatch", "us-east-1")
    inst_id = create_ec2_with_cpu(ec2, cw, 1.5)
    findings = sweeper.sweep_ec2(ec2, cw)
    assert inst_id in findings
    desc = ec2.describe_instances(InstanceIds=[inst_id])["Reservations"][0]["Instances"][0]
    assert desc["State"]["Name"] in ("stopping", "stopped")
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert tags.get("StoppedBy") == "FinOpsSweeper"


@mock_aws
def test_eip_unattached_found_and_released_on_real_run(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]
    findings = sweeper.sweep_eips(ec2)
    assert alloc_id in findings
    addrs = ec2.describe_addresses()["Addresses"]
    assert not any(a["AllocationId"] == alloc_id for a in addrs)


@mock_aws
def test_eip_associated_kept(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    inst = ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)["Instances"][0]
    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]
    ec2.associate_address(InstanceId=inst["InstanceId"], AllocationId=alloc_id)
    findings = sweeper.sweep_eips(ec2)
    assert alloc_id not in findings
    addrs = ec2.describe_addresses()["Addresses"]
    assert any(a["AllocationId"] == alloc_id for a in addrs)


@mock_aws
def test_eip_ignore_tag_skipped(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", False)
    ec2 = boto3.client("ec2", "us-east-1")
    alloc = ec2.allocate_address(
        Domain="vpc",
        TagSpecifications=[{
            "ResourceType": "elastic-ip",
            "Tags": [{"Key": "FinOps:Action", "Value": "Ignore"}],
        }],
    )
    alloc_id = alloc["AllocationId"]
    findings = sweeper.sweep_eips(ec2)
    assert alloc_id not in findings
    addrs = ec2.describe_addresses()["Addresses"]
    assert any(a["AllocationId"] == alloc_id for a in addrs)


@mock_aws
def test_eip_dry_run_changes_nothing(monkeypatch):
    monkeypatch.setattr(sweeper, "DRY_RUN", True)
    ec2 = boto3.client("ec2", "us-east-1")
    alloc = ec2.allocate_address(Domain="vpc")
    alloc_id = alloc["AllocationId"]
    findings = sweeper.sweep_eips(ec2)
    assert alloc_id in findings
    addrs = ec2.describe_addresses()["Addresses"]
    assert any(a["AllocationId"] == alloc_id for a in addrs)


@mock_aws
def test_scan_and_lambda_handler_single_account():
    session = boto3.Session()
    result = sweeper.scan(session)
    assert "ebs" in result
    assert "ec2" in result
    assert "eips" in result
    assert "elbs" in result

    summary = sweeper.lambda_handler({}, None)
    assert summary["dry_run"] is True
    assert summary["accounts_scanned"] == 1
    assert "findings" in summary
    assert summary["errors"] == []


def setup_subnets(ec2):
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sub1 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24", AvailabilityZone="us-east-1a")["Subnet"]["SubnetId"]
    sub2 = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone="us-east-1b")["Subnet"]["SubnetId"]
    return [sub1, sub2]


@mock_aws
def test_elb_orphaned_found():
    ec2 = boto3.client("ec2", "us-east-1")
    elbv2 = boto3.client("elbv2", "us-east-1")
    subnets = setup_subnets(ec2)
    lb = elbv2.create_load_balancer(Name="orphan-lb", Subnets=subnets)["LoadBalancers"][0]
    findings = sweeper.sweep_elbs(elbv2)
    assert lb["LoadBalancerArn"] in findings


@mock_aws
def test_elb_protected_skipped():
    ec2 = boto3.client("ec2", "us-east-1")
    elbv2 = boto3.client("elbv2", "us-east-1")
    subnets = setup_subnets(ec2)
    lb = elbv2.create_load_balancer(
        Name="prod-lb",
        Subnets=subnets,
        Tags=[{"Key": "Environment", "Value": "Production"}],
    )["LoadBalancers"][0]
    findings = sweeper.sweep_elbs(elbv2)
    assert lb["LoadBalancerArn"] not in findings


@mock_aws
def test_get_session_assumes_role():
    session = sweeper.get_session("123456789012")
    assert session is not None
    creds = session.get_credentials()
    assert creds is not None


@mock_aws
def test_multi_account_org_scan_partial_failure(monkeypatch):
    monkeypatch.setattr(sweeper, "SCAN_ORG", True)
    org = boto3.client("organizations", "us-east-1")
    org.create_organization(FeatureSet="ALL")
    spoke = org.create_account(Email="spoke@example.com", AccountName="SpokeAccount")["CreateAccountStatus"]
    spoke_id = spoke["AccountId"]
    master_id = DEFAULT_ACCOUNT_ID

    orig_get_session = sweeper.get_session

    def mock_get_session(account_id):
        if account_id == spoke_id:
            raise Exception(f"AccessDenied for spoke account {account_id}")
        return orig_get_session(account_id)

    monkeypatch.setattr(sweeper, "get_session", mock_get_session)

    summary = sweeper.lambda_handler({}, None)
    assert summary["accounts_scanned"] == 1
    assert master_id in summary["findings"]
    assert spoke_id not in summary["findings"]
    assert any(spoke_id in err for err in summary["errors"])


@mock_aws
def test_single_account_assumes_spoke_role(monkeypatch):
    monkeypatch.setattr(sweeper, "SCAN_ORG", False)
    assumed = []
    orig_get_session = sweeper.get_session

    def mock_get_session(account_id):
        assumed.append(account_id)
        return orig_get_session(account_id)

    monkeypatch.setattr(sweeper, "get_session", mock_get_session)

    summary = sweeper.lambda_handler({}, None)
    caller_account = boto3.client("sts", "us-east-1").get_caller_identity()["Account"]
    assert assumed == [caller_account]
    assert summary["accounts_scanned"] == 1
    assert summary["errors"] == []

