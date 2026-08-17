#!/usr/bin/env bash
#
# provision_management_box.sh
# ---------------------------
# Run ONCE from AWS CloudShell (browser — no laptop CLI needed).
# Creates a dedicated "patch-runner" EC2 with a least-privilege instance role,
# reachable via SSM Session Manager (no SSH key, no inbound ports).
#
# Why a dedicated box and not the Ansible node: the runner must NOT be in its
# own patch list, or it will reboot itself mid-run. This box is named so the
# walkthrough's env filter never selects it.
#
set -euo pipefail

# ------------------------- EDIT THESE FOUR -------------------------
REGION="eu-west-2"
SUBNET_ID="subnet-XXXXXXXX"      # a subnet with a path to the SSM endpoints
                                 #   (either a NAT gateway, or VPC endpoints for
                                 #    ssm, ssmmessages, ec2messages)
SECRET_ARN="arn:aws:secretsmanager:eu-west-2:ACCOUNTID:secret:splunk-admin-XXXXXX"
INSTANCE_TYPE="t3.small"
# -------------------------------------------------------------------

ROLE_NAME="patch-runner-role"
PROFILE_NAME="patch-runner-profile"
NAME="patch-runner"              # deliberately no dev/ref/prod -> never self-targeted

echo ">> Creating IAM role (EC2 trust)..."
cat > /tmp/trust.json <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF
aws iam create-role --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/trust.json >/dev/null 2>&1 || \
  echo "   (role already exists, continuing)"

echo ">> Attaching SSM connectivity policy (enables Session Manager)..."
aws iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

echo ">> Adding least-privilege patching policy..."
cat > /tmp/perms.json <<EOF
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"PatchOrchestration",
      "Effect":"Allow",
      "Action":[
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommandInvocations",
        "ssm:DescribeInstanceInformation",
        "ssm:DescribeInstancePatchStates",
        "ssm:DescribeInstancePatches",
        "ec2:DescribeInstances"
      ],
      "Resource":"*"
    },
    {
      "Sid":"SplunkSecretReadOnly",
      "Effect":"Allow",
      "Action":"secretsmanager:GetSecretValue",
      "Resource":"$SECRET_ARN"
    }
  ]
}
EOF
aws iam put-role-policy --role-name "$ROLE_NAME" \
  --policy-name patch-runner-perms --policy-document file:///tmp/perms.json

# NOTE ON HARDENING (see chat): the SendCommand Resource above is "*". To scope
# it to only your Splunk fleet, replace with instance ARNs plus a condition on
# tag Environment, and restrict the document to AWS-RunPatchBaseline /
# AWS-RunShellScript. Left broad here for first setup; tighten before prod.

echo ">> Creating instance profile..."
aws iam create-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1 || true
aws iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" \
  --role-name "$ROLE_NAME" >/dev/null 2>&1 || true
echo "   waiting for profile to propagate..."; sleep 12

echo ">> Resolving latest Amazon Linux 2023 AMI..."
AMI=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query "Parameters[0].Value" --output text)
echo "   AMI: $AMI"

echo ">> Launching $NAME ($INSTANCE_TYPE)..."
INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI" --instance-type "$INSTANCE_TYPE" \
  --iam-instance-profile Name="$PROFILE_NAME" \
  --subnet-id "$SUBNET_ID" \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
  --query "Instances[0].InstanceId" --output text)

echo ""
echo "=============================================================="
echo " Launched: $INSTANCE_ID"
echo " Give it ~2 min, then in the console:"
echo "   Systems Manager > Session Manager > Start session > $NAME"
echo ""
echo " On the box, install deps and fetch the script, e.g.:"
echo "   sudo dnf install -y python3-pip git"
echo "   pip3 install boto3"
echo "   # then git clone your repo, or aws s3 cp the script down"
echo "   #   (if using S3, add s3:GetObject on that bucket to the role)"
echo "=============================================================="
