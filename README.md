# Cloud Sweeper

Automated weekly waste remediation in a single account or across AWS Organizations using a Hub-and-Spoke model.
- **EBS**: unattached volumes older than `MIN_AGE_DAYS` (snapshots, then deletes).
- **EC2**: idle instances with 7-day max CPU < `CPU_THRESHOLD` (stops and tags `StoppedBy=FinOpsSweeper`).
- **EIP**: unattached Elastic IPs (releases).
- **ELB**: orphaned ALBs/NLBs with empty or unused targets (**REPORT ONLY**, never deletes).
All sweeps skip resources tagged `FinOps:Action=Ignore` or `Environment=Production`.

## Environment Variables
| Variable | Default | Purpose |
|---|---|---|
| `DRY_RUN` | `"true"` | Log actions without mutating AWS resources |
| `REGION` | `"us-east-1"` | Target AWS region to scan (`template.yaml` defaults to `"eu-north-1"`) |
| `CPU_THRESHOLD` | `5` | Maximum CPU percentage to flag idle EC2 |
| `MIN_AGE_DAYS` | `7` | Minimum unattached age in days before EBS deletion |
| `SPOKE_ROLE_NAME`| `"SpokeSweeperRole"` | IAM role assumed in spoke accounts |
| `SCAN_ORG` | `"false"` | Scan current account when `"false"` (assumes `SpokeSweeperRole` via STS); scan all org accounts when `"true"` (`template.yaml` sets `"false"`) |

## Testing & Deployment
```bash
pytest -v                                                        # Run moto unit tests
sam build && sam deploy --guided                                 # 1. Deploy Hub stack
aws cloudformation deploy --template-file spoke-role.yaml \     # 2. Deploy Spoke to EVERY account
  --stack-name SpokeSweeper --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides HubRoleArn=<HubRoleArnFromHubOutput>
```
Deploy `spoke-role.yaml` to **every** account (including the hub/single account) via CloudFormation StackSets.

## Safety & Operations
- **Dry Run**: Keep `DRY_RUN="true"` for several weeks; review findings before setting to `"false"`.
- **Snapshots**: Snapshots tagged `AutomatedSweeper=True` are never auto-deleted (clean up via DLM).
- **Production SCP**: Apply an SCP denying `ec2:StopInstances`, `ec2:DeleteVolume`, and `ec2:ReleaseAddress` to `SpokeSweeperRole` in production OUs.

## Later
Deferred items: SNS/Slack reports, SQS fan-out for large orgs, Cost Explorer savings report, in-use public IP audit, ELB deletion, and multi-region sweeps.
