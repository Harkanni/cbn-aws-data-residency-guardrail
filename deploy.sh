#!/usr/bin/env bash
# deploy.sh - run the single-account region-lock guardrail Terraform and test it on your real account.
#
# Run it from the folder that holds main.tf, with credentials for an IAM ADMIN user or role
# (not the root user). AWS CloudShell works well. Linux, macOS, WSL and CloudShell only.
#
#   ./deploy.sh install-tf   download Terraform to ~/bin (skip if you already have it)
#   ./deploy.sh bootstrap    ask AWS to enable the approved region in your account
#   ./deploy.sh check        verify tools, credentials, region, existing Config recorder
#   ./deploy.sh up           check + init + plan + (confirm) apply
#   ./deploy.sh test         live guardrail tests (denials, plus one allowed KMS upload)
#   ./deploy.sh status       Config rule compliance and SNS subscription state
#   ./deploy.sh drift        simulate an admin removing bucket encryption (Config should flag it)
#   ./deploy.sh fix          terraform apply to correct drift
#   ./deploy.sh destroy      tear everything down (asks first)
#   ./deploy.sh url          print the public live link (after ./deploy.sh up)
#   ./deploy.sh console      open the LIVE web console (runs server.py; real AWS calls)
#
# Settings come from terraform.tfvars or environment variables:
#   ALERT_EMAIL; optional APPROVED_REGION, NAME_PREFIX, TF_VERSION

set -euo pipefail
cd "$(dirname "$0")"

TF_VERSION="${TF_VERSION:-1.9.8}"
APPROVED_REGION="${APPROVED_REGION:-}"
FAILS=0
OP_AK=""; OP_SK=""; OP_ST=""

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
warn() { printf '  \033[33mWARN\033[0m %s\n' "$*"; }
die()  { printf '\033[31mERROR\033[0m %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed"; }

tfvar() {
  [ -f terraform.tfvars ] || return 0
  grep -E "^$1[[:space:]]*=" terraform.tfvars | head -1 | tr -d '\r' \
    | sed -E 's/^[^=]*=[[:space:]]*"?([^"#]*)"?.*/\1/' | xargs || true
}

load_vars() {
  ALERT_EMAIL="${ALERT_EMAIL:-$(tfvar alert_email)}"
  APPROVED_REGION="${APPROVED_REGION:-$(tfvar approved_region)}"; APPROVED_REGION="${APPROVED_REGION:-af-south-1}"
  NAME_PREFIX="${NAME_PREFIX:-$(tfvar name_prefix)}"; NAME_PREFIX="${NAME_PREFIX:-region-lock-demo}"
  [ -n "$ALERT_EMAIL" ] || die "alert_email not set (terraform.tfvars or ALERT_EMAIL)"
  export TF_VAR_alert_email="$ALERT_EMAIL" TF_VAR_approved_region="$APPROVED_REGION" TF_VAR_name_prefix="$NAME_PREFIX"
}

account_id() { aws sts get-caller-identity --query Account --output text | tr -d '\r'; }

assume() {
  [ -z "$OP_AK" ] || return 0
  local acct role i; acct="$(account_id)"; role="arn:aws:iam::${acct}:role/${NAME_PREFIX}-operator"
  for i in 1 2 3 4 5; do   # a new role can take a few seconds to become assumable
    if read -r OP_AK OP_SK OP_ST < <(aws sts assume-role --role-arn "$role" --role-session-name guardrail-demo \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text 2>/dev/null | tr -d '\r'); then return 0; fi
    sleep 5
  done
  die "cannot assume ${role}. Use an IAM admin user or role (not root), and run ./deploy.sh up first"
}

as_op() {
  AWS_ACCESS_KEY_ID="$OP_AK" AWS_SECRET_ACCESS_KEY="$OP_SK" AWS_SESSION_TOKEN="$OP_ST" "$@"
}

tf_out() {
  local v
  v="$(terraform output -raw "$1" 2>/dev/null | tr -d '\r')" || die "terraform output $1 not found; run ./deploy.sh up first"
  printf '%s' "$v"
}

# ---------------------------------------------------------------------------

cmd_install_tf() {
  if command -v terraform >/dev/null 2>&1; then ok "terraform already installed"; return; fi
  need curl
  local os arch a tmp file base
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"; arch="$(uname -m)"
  case "$arch" in x86_64) a=amd64 ;; aarch64|arm64) a=arm64 ;; *) die "unsupported CPU: $arch" ;; esac
  file="terraform_${TF_VERSION}_${os}_${a}.zip"
  base="https://releases.hashicorp.com/terraform/${TF_VERSION}"
  tmp="$(mktemp -d)"
  say "Downloading Terraform ${TF_VERSION}"
  curl -fsSL "${base}/${file}" -o "${tmp}/${file}" || die "download failed"
  curl -fsSL "${base}/terraform_${TF_VERSION}_SHA256SUMS" -o "${tmp}/SUMS" || die "checksum download failed"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && grep " ${file}\$" SUMS | sha256sum -c -) || die "checksum mismatch"
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$tmp" && grep " ${file}\$" SUMS | shasum -a 256 -c -) || die "checksum mismatch"
  else
    warn "no sha256 tool found; skipping checksum"
  fi
  if command -v unzip >/dev/null 2>&1; then unzip -q -o "${tmp}/${file}" -d "$tmp"
  else python3 -m zipfile -e "${tmp}/${file}" "$tmp"; fi
  mkdir -p "$HOME/bin"; mv "${tmp}/terraform" "$HOME/bin/terraform"; chmod +x "$HOME/bin/terraform"
  ok "installed to \$HOME/bin/terraform"
  echo "  Add it to your PATH now:  export PATH=\"\$HOME/bin:\$PATH\""
}

cmd_bootstrap() {
  need aws
  say "Enable ${APPROVED_REGION} in this account"
  aws account enable-region --region-name "$APPROVED_REGION" \
    && ok "region enable requested (takes a few minutes)" \
    || warn "failed; enable it in the console: Account settings > AWS Regions"
}

cmd_check() {
  say "Tools"
  if command -v terraform >/dev/null 2>&1; then ok "$(terraform version | head -1)"
  else bad "terraform missing (run: ./deploy.sh install-tf)"; fi
  need aws; ok "aws cli: $(aws --version 2>&1 | cut -d' ' -f1)"
  [ -f main.tf ] && ok "main.tf found" || die "main.tf not found next to this script"
  if [ -f hosting.tf ]; then
    local f missing=0
    for f in lambda/handler.py; do
      if [ -f "$f" ]; then ok "$f found"; else bad "$f missing"; missing=1; fi
    done
    if [ -f site/index.html ] || [ -f console.html ]; then ok "site page found"
    else bad "site/index.html (or console.html) missing"; missing=1; fi
    [ "$missing" -eq 0 ] || die "hosting.tf needs those files: copy them next to main.tf (keep the lambda/ and site/ folders), or delete hosting.tf to skip the public site"
  fi

  say "Credentials"
  local arn; arn="$(aws sts get-caller-identity --query Arn --output text)" || die "no valid AWS credentials"
  ok "caller: ${arn}"
  case "$arn" in
    *:root) die "you are using the root user. Create an IAM admin user (or use IAM Identity Center) and retry" ;;
  esac

  say "Region and Config"
  local opt rec
  opt="$(aws ec2 describe-regions --all-regions --region us-east-1 \
        --query "Regions[?RegionName=='${APPROVED_REGION}'].OptInStatus | [0]" --output text 2>/dev/null || true)"
  case "$opt" in
    opt-in-not-required|opted-in) ok "${APPROVED_REGION} is enabled" ;;
    not-opted-in) bad "${APPROVED_REGION} is not enabled (run: ./deploy.sh bootstrap, wait a few minutes)" ;;
    *) warn "could not read the region status (${opt:-no answer}); check the console under Account settings" ;;
  esac
  rec="$(aws configservice describe-configuration-recorders --region "$APPROVED_REGION" \
        --query 'ConfigurationRecorders[].name' --output text 2>/dev/null || true)"
  if [ -z "$rec" ] || [ "$rec" = "None" ]; then
    ok "no existing Config recorder"
  elif terraform state list 2>/dev/null | grep -qx 'aws_config_configuration_recorder.this'; then
    ok "Config recorder ${rec} is already managed by this Terraform state"
  else
    warn "a Config recorder (${rec}) exists in ${APPROVED_REGION} but is not in this Terraform state; only one is allowed, so apply will fail."
    echo "        If it is a leftover from an earlier run, remove it, then re-run check:"
    echo "          aws configservice stop-configuration-recorder --configuration-recorder-name ${rec} --region ${APPROVED_REGION}"
    echo "          aws configservice delete-delivery-channel --delivery-channel-name ${NAME_PREFIX}-channel --region ${APPROVED_REGION}"
    echo "          aws configservice delete-configuration-recorder --configuration-recorder-name ${rec} --region ${APPROVED_REGION}"
    echo "        Other leftovers show up as 'already exists' errors in the plan; delete or import each one."
  fi
}

cmd_init() { need terraform; terraform init -input=false; }
cmd_plan() { need terraform; terraform plan -input=false -out=tfplan; }

cmd_apply() {
  need terraform
  [ -f tfplan ] || cmd_plan
  terraform apply -input=false tfplan
  rm -f tfplan
  say "Next"
  echo "  1. Open the email sent to ${ALERT_EMAIL} and CONFIRM the SNS subscription."
  echo "  2. Run: ./deploy.sh test"
}

cmd_up() {
  cmd_check
  cmd_init
  cmd_plan
  read -r -p "Apply this plan? Type yes to continue: " a
  [ "$a" = "yes" ] || die "cancelled"
  cmd_apply
}

# --- live tests ------------------------------------------------------------

expect_denied() {
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    bad "${desc}: succeeded but should have been denied"; FAILS=$((FAILS+1))
  elif grep -qiE 'AccessDenied|UnauthorizedOperation|explicit deny' <<<"$out"; then
    ok "${desc}"; sed 's/^/        /' <<<"$out" | head -3
  else
    bad "${desc}: failed for another reason"; sed 's/^/        /' <<<"$out"; FAILS=$((FAILS+1))
  fi
}

expect_ok() {
  local desc="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then ok "${desc}"
  else bad "${desc}"; sed 's/^/        /' <<<"$out"; FAILS=$((FAILS+1)); fi
}

cmd_test() {
  need aws; need terraform; assume
  local acct bucket key tmp
  acct="$(account_id)"; bucket="$(tf_out payments_bucket)"; key="$(tf_out kms_key_arn)"
  tmp="$(mktemp -d)"; wtmp="$tmp"
  command -v cygpath >/dev/null 2>&1 && wtmp="$(cygpath -m "$tmp")"   # Git Bash: aws.exe needs C:/... paths
  echo '{"receipt_id":"cli-test","amount":1000,"note":"SIMULATED DATA"}' > "${tmp}/receipt.json"
  cat > "${tmp}/repl.json" <<EOF
{"Role":"arn:aws:iam::${acct}:role/dummy-replication-role",
 "Rules":[{"ID":"offshore","Status":"Enabled","Priority":1,"Filter":{},
 "DeleteMarkerReplication":{"Status":"Disabled"},
 "Destination":{"Bucket":"arn:aws:s3:::dummy-destination-bucket"}}]}
EOF

  say "1. Region lock (operator role policy): expect Access Denied  [screenshot 1]"
  expect_denied "describe VPCs in us-east-1" as_op aws ec2 describe-vpcs --region us-east-1
  expect_denied "create S3 bucket in us-east-1" as_op aws s3api create-bucket \
    --bucket "region-lock-denied-${acct}" --region us-east-1

  say "2. Replication and multi-Region keys: expect Access Denied  [alert email 1]"
  expect_denied "operator role: put bucket replication" as_op aws s3api put-bucket-replication \
    --bucket "$bucket" --replication-configuration "file://${wtmp}/repl.json" --region "$APPROVED_REGION"
  expect_denied "YOUR ADMIN identity: put bucket replication (bucket policy binds admins too)" aws s3api put-bucket-replication \
    --bucket "$bucket" --replication-configuration "file://${wtmp}/repl.json" --region "$APPROVED_REGION"
  expect_denied "operator role: create multi-Region KMS key" as_op aws kms create-key --multi-region --region "$APPROVED_REGION"

  say "3. Bucket policy: expect Access Denied for SSE-S3, success for our KMS key  [screenshot 2]"
  expect_denied "upload with SSE-S3 (AES256)" as_op aws s3api put-object --bucket "$bucket" \
    --key tests/sse-s3.json --body "${wtmp}/receipt.json" --server-side-encryption AES256 --region "$APPROVED_REGION"
  expect_ok "upload with our KMS key" as_op aws s3api put-object --bucket "$bucket" \
    --key tests/sse-kms.json --body "${wtmp}/receipt.json" --server-side-encryption aws:kms \
    --ssekms-key-id "$key" --region "$APPROVED_REGION"
  as_op aws s3api head-object --bucket "$bucket" --key tests/sse-kms.json --region "$APPROVED_REGION" \
    --query '{Encryption:ServerSideEncryption,Key:SSEKMSKeyId}' --output table || true

  rm -rf "$tmp"
  say "Result"
  if [ "$FAILS" -eq 0 ]; then ok "all guardrail tests behaved as expected"
  else bad "${FAILS} test(s) did not behave as expected"; exit 1; fi
  echo "  Note: the region lock binds the operator role only. Your own admin identity can still use other regions."
  echo "  Check your inbox for the replication alert, then run: ./deploy.sh status"
}

cmd_status() {
  need aws; need terraform
  say "Config rule compliance  [screenshot 3]"
  aws configservice describe-compliance-by-config-rule --region "$APPROVED_REGION" \
    --query 'ComplianceByConfigRules[].[ConfigRuleName,Compliance.ComplianceType]' --output table
  say "SNS subscription (must not be PendingConfirmation)"
  aws sns list-subscriptions-by-topic --region "$APPROVED_REGION" --topic-arn "$(tf_out alerts_topic_arn)" \
    --query 'Subscriptions[].[Endpoint,SubscriptionArn]' --output table
}

cmd_drift() {
  need aws; need terraform
  local bucket; bucket="$(tf_out payments_bucket)"
  say "Removing default encryption from ${bucket} (an admin change the guardrail policies do not block)"
  aws s3api delete-bucket-encryption --bucket "$bucket" --region "$APPROVED_REGION"
  ok "encryption removed"
  echo "  Config usually reports NON_COMPLIANT within a few minutes and an alert email follows  [screenshot 4]."
  echo "  Watch with: ./deploy.sh status      Correct it with: ./deploy.sh fix"
}

cmd_fix() { need terraform; terraform apply -input=false -auto-approve; }

cmd_destroy() {
  need terraform
  echo "  If you ran the migration demo, click 'Reset migration' in the console first; the migrated server and image are created at run time and Terraform does not know about them."
  read -r -p "Destroy ALL guardrail resources? Type destroy to continue: " a
  [ "$a" = "destroy" ] || die "cancelled"
  terraform destroy -input=false -auto-approve
  echo "  The KMS key is scheduled for deletion in 7 days; it can still be billed until then."
}

usage() { sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; }

case "${1:-help}" in
  install-tf) cmd_install_tf ;;
  bootstrap)  load_vars; cmd_bootstrap ;;
  check)      load_vars; cmd_check ;;
  init)       load_vars; cmd_init ;;
  plan)       load_vars; cmd_plan ;;
  apply)      load_vars; cmd_apply ;;
  up)         load_vars; cmd_up ;;
  test)       load_vars; cmd_test ;;
  status)     load_vars; cmd_status ;;
  drift)      load_vars; cmd_drift ;;
  fix)        load_vars; cmd_fix ;;
  destroy)    load_vars; cmd_destroy ;;
  url)        need terraform; terraform output -raw site_url; echo ;;
  console)    load_vars; need aws; exec py server.py ;;
  *)          usage ;;
esac
