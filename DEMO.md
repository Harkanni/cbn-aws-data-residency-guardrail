# Terminal proof: commands for the live demo

Run these in AWS CloudShell (af-south-1) from the repo folder, signed in as an IAM admin user or role (not root).
Every "Denied" below is AWS's own authorization decision.

**Before the session:** run step 9a first. AWS Config takes a few minutes to flag drift, so it will be ready when you reach it.

## 0. Setup

```bash
export AWS_REGION=af-south-1
BUCKET=$(terraform output -raw payments_bucket)
KEY=$(terraform output -raw kms_key_arn)
ROLE=$(terraform output -raw guardrail_role_arn)
ACCT=$(aws sts get-caller-identity --query Account --output text)

# helper: become a role / go back to your admin identity
as_role() { eval "$(aws sts assume-role --role-arn "$1" --role-session-name demo \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text |
  awk '{print "export AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_SESSION_TOKEN="$3}')"; aws sts get-caller-identity --query Arn --output text; }
as_admin() { unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN; aws sts get-caller-identity --query Arn --output text; }
```

## 1. Who am I, and what is deployed

```bash
aws sts get-caller-identity            # an admin, before any guardrail
terraform state list                   # everything is code
```

## 2. Ask IAM first (no side effects)

Same actions, opposite answers, decided only by region:

```bash
for R in eu-west-1 us-east-1 af-south-1; do echo "== $R"
  aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
    --action-names ec2:RunInstances s3:CreateBucket rds:CreateDBInstance \
    --context-entries "ContextKeyName=aws:RequestedRegion,ContextKeyValues=$R,ContextKeyType=string" \
    --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
done
```

## 3. Region lock (as the operator role)

```bash
as_role "$ROLE"
aws ec2 describe-vpcs --region af-south-1 --query 'length(Vpcs)'           # Allowed
aws ec2 describe-vpcs --region eu-west-1                                    # Denied
aws s3api create-bucket --bucket "offshore-$ACCT" --region us-east-1        # Denied
```

## 4. No copies out: replication and multi-Region keys

```bash
cat > /tmp/repl.json <<EOF
{"Role":"arn:aws:iam::$ACCT:role/dummy","Rules":[{"ID":"offshore","Status":"Enabled","Priority":1,
"Filter":{},"DeleteMarkerReplication":{"Status":"Disabled"},
"Destination":{"Bucket":"arn:aws:s3:::dummy-destination"}}]}
EOF
aws s3api put-bucket-replication --bucket "$BUCKET" --replication-configuration file:///tmp/repl.json   # Denied
aws kms create-key --multi-region                                                                       # Denied
```

## 5. The role cannot remove its own guardrails

```bash
aws iam detach-role-policy --role-name region-lock-demo-operator \
  --policy-arn "arn:aws:iam::$ACCT:policy/region-lock-demo-deny-outside-approved-region"               # Denied
```

## 6. The bank's key, TLS only

```bash
echo '{"receipt":"demo","amount":5000,"currency":"NGN","note":"SIMULATED"}' > /tmp/r.json
aws s3api put-object --bucket "$BUCKET" --key tests/a.json --body /tmp/r.json --server-side-encryption AES256           # Denied
aws s3api put-object --bucket "$BUCKET" --key tests/b.json --body /tmp/r.json \
  --server-side-encryption aws:kms --ssekms-key-id alias/aws/s3                                                      # Denied (not our key)
aws s3api put-object --bucket "$BUCKET" --key tests/c.json --body /tmp/r.json \
  --endpoint-url http://s3.af-south-1.amazonaws.com                                                                  # Denied (no TLS)
aws s3api put-object --bucket "$BUCKET" --key tests/d.json --body /tmp/r.json \
  --server-side-encryption aws:kms --ssekms-key-id "$KEY"                                                            # Allowed
aws s3api head-object --bucket "$BUCKET" --key tests/d.json --query '{Enc:ServerSideEncryption,Key:SSEKMSKeyId}' --output table
```

## 7. Even your admin can't copy data out

```bash
as_admin
aws s3api put-bucket-replication --bucket "$BUCKET" --replication-configuration file:///tmp/repl.json   # Denied: bucket policy binds everyone
aws kms describe-key --key-id "$KEY" --query 'KeyMetadata.{MultiRegion:MultiRegion,Manager:KeyManager}' --output table
aws kms get-key-rotation-status --key-id "$KEY"
```

## 8. Migration: inbound only (eu-west-1 → af-south-1)

These match the migration in the architecture diagram. The first block finds the resource names.

```bash
MIGRATOR=$(aws iam list-roles --query "Roles[?contains(RoleName,'migrator')].Arn | [0]" --output text); echo "$MIGRATOR"
aws dynamodb list-tables --region eu-west-1      # legacy payments table
aws dynamodb list-tables --region af-south-1     # migrated payments table
LEGACY_TABLE=<legacy table name>; NEW_TABLE=<migrated table name>
```

What landed in Nigeria's stand-in region, and under whose key:

```bash
aws dynamodb describe-table --table-name "$NEW_TABLE" --region af-south-1 \
  --query 'Table.{Items:ItemCount,SSE:SSEDescription.SSEType,Key:SSEDescription.KMSMasterKeyArn}' --output table
aws dynamodb scan --table-name "$NEW_TABLE" --region af-south-1 --select COUNT
aws ec2 describe-images --owners self --region af-south-1 \
  --query 'Images[].[Name,BlockDeviceMappings[0].Ebs.Encrypted,BlockDeviceMappings[0].Ebs.KmsKeyId]' --output table
aws ec2 describe-instances --region af-south-1 --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].[InstanceId,ImageId,State.Name]' --output table
```

The migrator can read from offshore but cannot write anywhere except af-south-1:

```bash
as_role "$MIGRATOR"
aws dynamodb scan --table-name "$LEGACY_TABLE" --region eu-west-1 --select COUNT                           # Allowed (read in)
aws dynamodb put-item --table-name "$LEGACY_TABLE" --region eu-west-1 \
  --item '{"id":{"S":"out-test"}}'                                                                          # Denied (write out)
aws s3api create-bucket --bucket "offshore-copy-$ACCT" --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1                                                # Denied
as_admin
```

If `id` isn't the table's key name, check it with `aws dynamodb describe-table --table-name "$LEGACY_TABLE" --region eu-west-1 --query Table.KeySchema`.

## 9. Evidence: drift, alerts, audit trail

```bash
./deploy.sh drift       # 9a: run at the start. An admin removes bucket encryption
./deploy.sh status      # later: s3-default-encryption-kms = NON_COMPLIANT, email arrives
./deploy.sh fix         # terraform apply restores it; back to COMPLIANT
```

Every denied attempt above, from the audit trail:

```bash
aws cloudtrail lookup-events --max-results 20 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketReplication \
  --query 'Events[].CloudTrailEvent' --output text |
  jq -r '[.eventTime, .userIdentity.arn, .eventName, (.errorCode // "allowed")] | @tsv'
```

Alerts actually fired (last 24 hours):

```bash
for RULE in region-lock-demo-replication-change region-lock-demo-config-noncompliant; do
  echo -n "$RULE: "
  aws cloudwatch get-metric-statistics --namespace AWS/Events --metric-name Invocations \
    --dimensions Name=RuleName,Value=$RULE --statistics Sum --period 86400 \
    --start-time "$(date -u -d '-24 hours' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)" \
    --query 'Datapoints[0].Sum' --output text
done
aws sns list-subscriptions-by-topic --topic-arn "$(terraform output -raw alerts_topic_arn)" \
  --query 'Subscriptions[].SubscriptionArn' --output text        # must not say PendingConfirmation
```

## 10. One-shot backup

If anything misbehaves live, this runs the core checks with PASS/FAIL:

```bash
./deploy.sh test
```

## 11. Hand over to the web console

```bash
./deploy.sh url          # share this link: anyone can run the safe probes and WATCH the migration live
./deploy.sh demo-key     # type this into "Presenter mode" on the page to unlock migration, drift and fix
curl -s "$(terraform output -raw site_url)/api/status" | jq '{rules, config, fired}'
curl -s "$(terraform output -raw site_url)/api/migration" | jq '{legacy, dest, job}'   # the public live view
```

Start "Migrate the EC2 server" early: the image copy takes several minutes, and viewers see the
progress live. Click "Reset migration" before `./deploy.sh destroy`.
