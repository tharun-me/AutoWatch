import boto3
import json
import time
import logging
import os
import re

from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

# ============================================================
# LOGGING
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ============================================================
# REGION
# ============================================================

REGION = boto3.session.Session().region_name

# ============================================================
# AWS CLIENTS
# ============================================================

ec2 = boto3.client(
    "ec2",
    region_name=REGION
)

iam = boto3.client("iam")

ssm = boto3.client(
    "ssm",
    region_name=REGION
)

cloudwatch = boto3.client(
    "cloudwatch",
    region_name=REGION
)

# ============================================================
# ENVIRONMENT VARIABLES
# ============================================================

# SNS Topic ARN for alarm notifications
# e.g. arn:aws:sns:ap-south-1:123456789012:MyAlertTopic
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")

# Client name to embed in alarm names
# e.g. "AcmeCorp"
CLIENT_NAME = os.environ.get("CLIENT_NAME", "Client")

# Account friendly name to embed in alarm names
# e.g. "Production"
ACCOUNT_NAME = os.environ.get("ACCOUNT_NAME", "Account")

# ============================================================
# REQUIRED IAM POLICIES
# ============================================================

REQUIRED_POLICIES = {

    "AmazonSSMManagedInstanceCore":
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",

    "CloudWatchAgentServerPolicy":
        "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# ============================================================
# LINUX CLOUDWATCH CONFIG
# ============================================================

# Linux CW Agent config — Ubuntu & Amazon Linux.
# Custom metrics collected (on top of default EC2 metrics):
#   disk_used_percent  : disk usage % per mount point
#   mem_used_percent   : memory usage %
LINUX_CONFIG = {

    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "root"
    },

    "metrics": {

        "namespace": "CWAgent",

        "append_dimensions": {

            "InstanceId": "${aws:InstanceId}",
            "InstanceType": "${aws:InstanceType}",
            "ImageId": "${aws:ImageId}"
        },

        "aggregation_dimensions": [
            ["InstanceId"]
        ],

        "metrics_collected": {

            "mem": {

                "measurement": [
                    "mem_used_percent"
                ],

                "metrics_collection_interval": 60
            },

            "disk": {

                "measurement": [
                    "used_percent"
                ],

                "resources": [
                    "*"
                ],

                "metrics_collection_interval": 60,

                "ignore_file_system_types": [
                    "sysfs",
                    "devtmpfs",
                    "tmpfs",
                    "overlay",
                    "squashfs"
                ]
            }
        }
    }
}

# ============================================================
# WINDOWS CLOUDWATCH CONFIG
# ============================================================

# Windows CW Agent config.
# Custom metrics collected (on top of default EC2 metrics):
#   LogicalDisk % Free Space    : free disk space % per volume
#   LogicalDisk Free Megabytes  : free disk space in MB per volume
#   Memory % Committed Bytes In Use  : memory usage %
WINDOWS_CONFIG = {

    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "Administrator"
    },

    "metrics": {

        "namespace": "CWAgent",

        "append_dimensions": {

            "InstanceId": "${aws:InstanceId}",
            "InstanceType": "${aws:InstanceType}",
            "ImageId": "${aws:ImageId}"
        },

        "aggregation_dimensions": [
            ["InstanceId"]
        ],

        "metrics_collected": {

            "Memory": {

                "measurement": [
                    "% Committed Bytes In Use"
                ],

                "metrics_collection_interval": 60
            },

            "LogicalDisk": {

                "measurement": [
                    "% Free Space",
                    "Free Megabytes"
                ],

                "metrics_collection_interval": 60,

                "resources": [
                    "*"
                ]
            }
        }
    }
}

# ============================================================
# SANITIZE ROLE NAME
# ============================================================

def sanitize_name(name):

    clean = re.sub(
        r'[^A-Za-z0-9+=,.@_-]',
        '_',
        name
    )

    return clean[:60]

# ============================================================
# SANITIZE ALARM NAME
# ============================================================

def sanitize_alarm_name(name):
    """
    CloudWatch alarm names allow alphanumerics, spaces, and: . - _ # : ( )
    Replace anything else with a space and collapse extra spaces.
    Max 256 chars.
    """
    clean = re.sub(
        r'[^A-Za-z0-9 ._()\-:#|]',
        ' ',
        name
    )

    clean = re.sub(r' +', ' ', clean).strip()

    return clean[:256]

# ============================================================
# GET INSTANCE DETAILS
# ============================================================

def get_instance_details(instance_id):

    response = ec2.describe_instances(
        InstanceIds=[instance_id]
    )

    reservations = response.get(
        "Reservations",
        []
    )

    if not reservations:
        return None

    instance = reservations[0]["Instances"][0]

    tags = {
        tag["Key"]: tag["Value"]
        for tag in instance.get("Tags", [])
    }

    instance_name = tags.get(
        "Name",
        instance_id
    )

    platform = instance.get(
        "Platform",
        "linux"
    ).lower()

    os_type = (
        "windows"
        if platform == "windows"
        else "linux"
    )

    profile_name = None

    if instance.get("IamInstanceProfile"):

        profile_arn = (
            instance["IamInstanceProfile"]["Arn"]
        )

        profile_name = (
            profile_arn.split("/")[-1]
        )

    image_id      = instance.get("ImageId", "")
    instance_type = instance.get("InstanceType", "")

    return {

        "instance": instance,

        "tags": tags,

        "instance_name": instance_name,

        "os_type": os_type,

        "profile_name": profile_name,

        "image_id": image_id,

        "instance_type": instance_type
    }

# ============================================================
# VALIDATE INSTANCE — wait for running state
# ============================================================

def validate_instance(instance_id):
    """
    Wait up to 10 minutes (60 x 10 s) for the instance to reach
    'running'. EventBridge tag-change events fire while the instance
    is still in 'pending', so an immediate state check is too early.
    Raises if the instance reaches a terminal bad state or times out.
    """

    logger.info(
        "========== WAITING FOR INSTANCE RUNNING =========="
    )

    terminal_bad = {"shutting-down", "terminated", "stopping", "stopped"}

    for attempt in range(60):

        response = ec2.describe_instances(
            InstanceIds=[instance_id]
        )

        reservations = response.get("Reservations", [])

        if not reservations:
            raise Exception(
                f"Instance disappeared while waiting : {instance_id}"
            )

        instance = reservations[0]["Instances"][0]
        state    = instance["State"]["Name"]

        logger.info(
            f"Instance State : {state}  (attempt {attempt + 1}/60)"
        )

        if state == "running":
            logger.info("Instance is running")
            return instance          # return refreshed instance object

        if state in terminal_bad:
            raise Exception(
                f"Instance entered terminal state while waiting : {state}"
            )

        time.sleep(10)

    raise Exception(
        "Timed out waiting for instance to reach running state"
    )

# ============================================================
# CREATE IAM ROLE
# ============================================================

def create_role(role_name):

    logger.info(
        f"Creating IAM Role : {role_name}"
    )

    trust_policy = {

        "Version": "2012-10-17",

        "Statement": [
            {
                "Effect": "Allow",

                "Principal": {
                    "Service": "ec2.amazonaws.com"
                },

                "Action": "sts:AssumeRole"
            }
        ]
    }

    iam.create_role(

        RoleName=role_name,

        AssumeRolePolicyDocument=json.dumps(
            trust_policy
        ),

        Description="Auto created monitoring role"
    )

    logger.info("IAM Role Created")

    time.sleep(15)

# ============================================================
# ENSURE POLICIES
# ============================================================

def ensure_policies(role_name):

    attached = iam.list_attached_role_policies(
        RoleName=role_name
    )["AttachedPolicies"]

    existing = [
        p["PolicyName"]
        for p in attached
    ]

    for policy_name, policy_arn in REQUIRED_POLICIES.items():

        if policy_name in existing:

            logger.info(
                f"Policy Already Attached : {policy_name}"
            )

        else:

            logger.info(
                f"Attaching Policy : {policy_name}"
            )

            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=policy_arn
            )

            logger.info(
                f"Attached : {policy_name}"
            )

# ============================================================
# ENSURE INSTANCE PROFILE
# ============================================================

def ensure_instance_profile(role_name):

    try:

        iam.get_instance_profile(
            InstanceProfileName=role_name
        )

        logger.info(
            f"Instance Profile Exists : {role_name}"
        )

    except iam.exceptions.NoSuchEntityException:

        logger.info(
            f"Creating Instance Profile : {role_name}"
        )

        iam.create_instance_profile(
            InstanceProfileName=role_name
        )

        time.sleep(15)

    profile = iam.get_instance_profile(
        InstanceProfileName=role_name
    )["InstanceProfile"]

    existing_roles = [
        r["RoleName"]
        for r in profile["Roles"]
    ]

    if role_name not in existing_roles:

        logger.info(
            f"Adding Role To Profile : {role_name}"
        )

        retry = 0

        while retry < 5:

            try:

                iam.add_role_to_instance_profile(

                    InstanceProfileName=role_name,

                    RoleName=role_name
                )

                logger.info(
                    "Role Added Successfully"
                )

                break

            except ClientError as e:

                retry += 1

                logger.warning(
                    f"IAM Delay Retry {retry}/5 : {str(e)}"
                )

                time.sleep(10)

    return profile["Arn"]

# ============================================================
# ATTACH INSTANCE PROFILE
# ============================================================

def attach_profile(
    instance_id,
    profile_arn
):

    response = (
        ec2.describe_iam_instance_profile_associations(
            Filters=[
                {
                    "Name": "instance-id",
                    "Values": [instance_id]
                }
            ]
        )
    )

    associations = response.get(
        "IamInstanceProfileAssociations",
        []
    )

    valid_states = [
        "associated",
        "associating"
    ]

    for association in associations:

        state = association["State"]

        if state in valid_states:

            logger.info(
                f"IAM Profile Already Attached : {state}"
            )

            return

    logger.info("Attaching IAM Profile")

    ec2.associate_iam_instance_profile(

        IamInstanceProfile={
            "Arn": profile_arn
        },

        InstanceId=instance_id
    )

    logger.info("IAM Profile Attached")

    logger.info(
        "Waiting For IAM Propagation..."
    )

    time.sleep(60)

# ============================================================
# ENSURE ROLE SETUP
# ============================================================

def ensure_role_setup(
    instance_id,
    instance_name,
    profile_name
):

    clean_name = sanitize_name(
        instance_name
    )

    role_name = f"{clean_name}_role"

    logger.info(
        f"Target Role Name : {role_name}"
    )

    if profile_name:

        logger.info(
            f"Existing Instance Profile : {profile_name}"
        )

        profile = iam.get_instance_profile(
            InstanceProfileName=profile_name
        )["InstanceProfile"]

        if not profile["Roles"]:

            raise Exception(
                "No role attached in instance profile"
            )

        existing_role = (
            profile["Roles"][0]["RoleName"]
        )

        logger.info(
            f"Existing Role : {existing_role}"
        )

        ensure_policies(existing_role)

        return existing_role

    try:

        iam.get_role(
            RoleName=role_name
        )

        logger.info(
            f"Role Already Exists : {role_name}"
        )

    except iam.exceptions.NoSuchEntityException:

        create_role(role_name)

    ensure_policies(role_name)

    profile_arn = ensure_instance_profile(
        role_name
    )

    attach_profile(
        instance_id,
        profile_arn
    )

    return role_name

# ============================================================
# WAIT FOR SSM
# ============================================================

def wait_for_ssm(instance_id):

    logger.info(
        "========== WAITING FOR SSM =========="
    )

    for attempt in range(36):

        response = (
            ssm.describe_instance_information(
                Filters=[
                    {
                        "Key": "InstanceIds",
                        "Values": [instance_id]
                    }
                ]
            )
        )

        instances = response.get(
            "InstanceInformationList",
            []
        )

        if instances:

            status = instances[0].get(
                "PingStatus"
            )

            logger.info(
                f"SSM Status : {status}"
            )

            if status == "Online":

                logger.info(
                    "SSM Connected"
                )

                return True

        logger.info(
            f"Retrying SSM Check {attempt + 1}/36"
        )

        time.sleep(10)

    raise Exception(
        "SSM Agent Not Online"
    )

# ============================================================
# RUN SSM COMMAND
# ============================================================

def run_ssm_command(
    instance_id,
    commands,
    comment,
    os_type
):

    document = (
        "AWS-RunPowerShellScript"
        if os_type == "windows"
        else "AWS-RunShellScript"
    )

    logger.info(
        f"Running SSM Command : {comment}"
    )

    response = ssm.send_command(

        InstanceIds=[instance_id],

        DocumentName=document,

        Parameters={
            "commands": commands
        },

        TimeoutSeconds=3600,

        Comment=comment
    )

    command_id = (
        response["Command"]["CommandId"]
    )

    logger.info(
        f"Command ID : {command_id}"
    )

    for _ in range(120):

        time.sleep(10)

        try:

            result = ssm.get_command_invocation(

                CommandId=command_id,

                InstanceId=instance_id
            )

            status = result["Status"]

            logger.info(
                f"Command Status : {status}"
            )

            if status == "Success":

                stdout = result.get(
                    "StandardOutputContent",
                    ""
                )

                logger.info(
                    f"STDOUT:\n{stdout}"
                )

                return stdout

            if status in [
                "Failed",
                "Cancelled",
                "TimedOut",
                "DeliveryTimedOut"
            ]:

                stderr = result.get(
                    "StandardErrorContent",
                    ""
                )

                logger.error(
                    f"STDERR:\n{stderr}"
                )

                raise Exception(stderr)

        except ClientError as e:

            logger.warning(
                f"Waiting Invocation : {str(e)}"
            )

    raise Exception(
        "SSM Command Timeout"
    )

# ============================================================
# INSTALL CLOUDWATCH AGENT
# ============================================================

def install_cloudwatch_agent(
    instance_id,
    os_type
):

    logger.info(
        "========== INSTALLING CLOUDWATCH AGENT =========="
    )

    # ========================================================
    # WINDOWS
    # ========================================================

    if os_type == "windows":

        commands = [

r'''
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$agentPath = "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1"

if (Test-Path $agentPath) {

    Write-Output "CloudWatch Agent Already Installed"

} else {

    $msiPath = "$env:TEMP\amazon-cloudwatch-agent.msi"

    Invoke-WebRequest `
    -Uri "https://amazoncloudwatch-agent.s3.amazonaws.com/windows/amd64/latest/amazon-cloudwatch-agent.msi" `
    -OutFile $msiPath

    $process = Start-Process msiexec.exe `
    -Wait `
    -PassThru `
    -ArgumentList "/i `"$msiPath`" /qn"

    if ($process.ExitCode -ne 0) {

        throw "CloudWatch Agent MSI Install Failed"
    }

    Start-Sleep -Seconds 20
}

# FIX: Do NOT call Start-Service here.
# The CW Agent service requires a valid config file to start.
# Without config it crashes immediately, leaving a corrupt state.
# The service will be started after fetch-config in the configure step.
Set-Service AmazonCloudWatchAgent -StartupType Automatic

Write-Output "Agent installed. Service startup deferred until config is applied."

Get-Service AmazonCloudWatchAgent
'''
        ]

        return run_ssm_command(
            instance_id,
            commands,
            "Install CW Agent Windows",
            os_type
        )

    # ========================================================
    # LINUX
    # ========================================================

    commands = [

        "set -e",

        '''
if [ -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    echo "CloudWatch Agent Already Installed"
    exit 0
fi
''',

        '''
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

echo "Detected OS : $OS"
''',

        "mkdir -p /tmp/cwagent",

        "cd /tmp/cwagent",

        '''
if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then

    curl -fsSL -O https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb

    dpkg -i -E amazon-cloudwatch-agent.deb
fi
''',

        '''
if [ "$OS" = "amzn" ] || \
   [ "$OS" = "rhel" ] || \
   [ "$OS" = "centos" ] || \
   [ "$OS" = "rocky" ] || \
   [ "$OS" = "almalinux" ]; then

    curl -fsSL -O https://amazoncloudwatch-agent.s3.amazonaws.com/redhat/amd64/latest/amazon-cloudwatch-agent.rpm

    rpm -Uvh amazon-cloudwatch-agent.rpm
fi
''',

        '''
if [ ! -f /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl ]; then
    echo "CloudWatch Agent Installation Failed"
    exit 1
fi
''',

        "systemctl daemon-reload",

        # Only enable — do NOT start or restart here.
        # The agent has no config yet and exits with code 3,
        # which aborts the whole script because of set -e at the top.
        # The configure step writes the config and restarts the service.
        "systemctl enable amazon-cloudwatch-agent",

        "echo 'Agent installed. Service startup deferred until config is applied.'"
    ]

    return run_ssm_command(
        instance_id,
        commands,
        "Install CW Agent Linux",
        os_type
    )

# ============================================================
# CONFIGURE CLOUDWATCH AGENT
# ============================================================

def configure_cloudwatch_agent(
    instance_id,
    os_type
):

    logger.info(
        "========== CONFIGURING CLOUDWATCH AGENT =========="
    )

    # ========================================================
    # WINDOWS CONFIGURATION
    # ========================================================

    if os_type == "windows":

        config = json.dumps(
            WINDOWS_CONFIG,
            indent=4
        )

        # ----------------------------------------------------
        # FIX: Use single-quoted here-string @'...'@ instead
        # of double-quoted @"..."@.
        #
        # PowerShell double-quoted here-strings expand variables
        # like ${aws:InstanceId} to empty strings at runtime,
        # which causes the CloudWatch agent config-translator to
        # reject the JSON with:
        #   "String length must be greater than or equal to 1"
        #
        # Single-quoted here-strings treat all content as
        # literal text, so ${aws:InstanceId} is written to the
        # file exactly as intended.
        # ----------------------------------------------------

        commands = [

r'''
New-Item `
-ItemType Directory `
-Force `
-Path "C:\ProgramData\Amazon\AmazonCloudWatchAgent" | Out-Null
''',

# FIX 1: Use single-quoted here-string @'...'@ so PowerShell does
# not expand ${aws:InstanceId} etc. to empty strings at runtime.
#
# FIX 2: Use [System.IO.File]::WriteAllText with an explicit
# no-BOM UTF-8 encoding object instead of Set-Content -Encoding UTF8.
# On Windows PowerShell 5.1, Set-Content -Encoding UTF8 ALWAYS
# prepends a UTF-8 BOM (EF BB BF). The CW agent JSON parser sees
# the BOM as invalid character 'ï', falls back to its internal
# default config, produces a bad TOML, and the agent binary crashes
# on startup with error 1053 (no log file is ever written).
# New-Object System.Text.UTF8Encoding $false gives true BOM-free
# UTF-8 in both PowerShell 5.1 and PowerShell 7+.
rf'''
$configJson = @'
{config}
'@
$configPath = "C:\ProgramData\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($configPath, $configJson, $utf8NoBom)
Write-Output "Config written (UTF-8 without BOM)"
''',

# FIX: Stop the service cleanly before reconfiguring.
r'''
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" `
-a stop
''',

# FIX: Delete stale translated configs from any previous failed run.
# If a corrupt TOML is left in Configs\ from a prior attempt,
# fetch-config will re-use it and the service will refuse to start.
r'''
$configsDir = "C:\ProgramData\Amazon\AmazonCloudWatchAgent\Configs"
if (Test-Path $configsDir) {
    Remove-Item "$configsDir\*" -Force -ErrorAction SilentlyContinue
    Write-Output "Cleared stale config files"
}
''',

# FIX: Run fetch-config WITHOUT the -s flag.
# The -s flag internally calls Start-Service inside the ctl script.
# If that Start-Service fails it throws an uncatchable terminating
# error that fails the whole SSM command. We start the service
# ourselves in the next step so we get a clean, visible error.
r'''
& "C:\Program Files\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent-ctl.ps1" `
-a fetch-config `
-m ec2 `
-c file:"C:\ProgramData\Amazon\AmazonCloudWatchAgent\amazon-cloudwatch-agent.json"

Write-Output "fetch-config completed"
''',

r'''
Set-Service AmazonCloudWatchAgent -StartupType Automatic
''',

# Start the service explicitly so any error is clear and isolated.
r'''
try {
    Start-Service AmazonCloudWatchAgent -ErrorAction Stop
    Write-Output "Service started successfully"
} catch {
    Write-Output "Start-Service error: $_"
    Write-Output "Attempting sc.exe start as fallback..."
    sc.exe start AmazonCloudWatchAgent
    Start-Sleep -Seconds 5
}
''',

r'''
Start-Sleep -Seconds 20
''',

r'''
Get-Service AmazonCloudWatchAgent
''',

r'''
if (Test-Path "C:\ProgramData\Amazon\AmazonCloudWatchAgent\Logs\amazon-cloudwatch-agent.log") {
    Get-Content `
    "C:\ProgramData\Amazon\AmazonCloudWatchAgent\Logs\amazon-cloudwatch-agent.log" `
    -Tail 50
} else {
    Write-Output "Log file not found yet"
}
'''
        ]

    # ========================================================
    # LINUX CONFIGURATION
    # ========================================================

    else:

        config = json.dumps(
            LINUX_CONFIG,
            indent=4
        )

        commands = [

            "mkdir -p /opt/aws/amazon-cloudwatch-agent/etc",

f"""cat <<'EOF' > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
{config}
EOF""",

            "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a stop",

            "/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl "
            "-a fetch-config "
            "-m ec2 "
            "-c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json "
            "-s",

            "systemctl restart amazon-cloudwatch-agent",

            "systemctl enable amazon-cloudwatch-agent",

            "sleep 10",

            "systemctl status amazon-cloudwatch-agent --no-pager",

            "cat /opt/aws/amazon-cloudwatch-agent/logs/amazon-cloudwatch-agent.log | tail -50"
        ]

    return run_ssm_command(
        instance_id,
        commands,
        "Configure CW Agent",
        os_type
    )

# ============================================================
# VERIFY METRICS
# ============================================================

def verify_metrics(instance_id, os_type):

    logger.info(
        "========== VERIFYING METRICS =========="
    )

    logger.info(
        f"Checking Metrics For OS : {os_type}"
    )

    # FIX: Use list_metrics instead of get_metric_statistics.
    #
    # get_metric_statistics requires ALL dimensions to match exactly.
    # Windows CW Agent metrics are published with multiple dimensions:
    #   InstanceId + objectname + instance (e.g. "_Total", "C:", etc.)
    # Querying with only InstanceId returns nothing even though the
    # metrics exist and are visible in the dashboard.
    #
    # list_metrics does partial dimension matching — filtering by
    # InstanceId alone finds any CWAgent metric for that instance,
    # regardless of what other dimensions are present.
    # This works for both Windows and Linux without hardcoding names.

    for attempt in range(12):

        try:

            response = cloudwatch.list_metrics(

                Namespace="CWAgent",

                Dimensions=[
                    {
                        "Name": "InstanceId",
                        "Value": instance_id
                    }
                ]
            )

            metrics = response.get(
                "Metrics",
                []
            )

            if metrics:

                logger.info(
                    f"Metrics Found : {len(metrics)} metrics published"
                )

                for m in metrics[:5]:

                    logger.info(
                        f"Sample Metric : {m['MetricName']} "
                        f"Dimensions : {m['Dimensions']}"
                    )

                return True

        except Exception as e:

            logger.warning(
                f"Metric List Failed : {str(e)}"
            )

        logger.info(
            f"Waiting For Metrics Retry {attempt + 1}/12"
        )

        time.sleep(30)

    return False

# ============================================================
# ENABLE DETAILED MONITORING
# ============================================================

def enable_detailed_monitoring(instance_id):

    try:

        ec2.monitor_instances(
            InstanceIds=[instance_id]
        )

        logger.info(
            "Detailed Monitoring Enabled"
        )

    except Exception as e:

        logger.warning(
            f"Detailed Monitoring Failed : {str(e)}"
        )

# ============================================================
# BUILD ALARM NAME
# ============================================================

def build_alarm_name(severity, server_name, metric_label):
    """
    Format: Severity || Client Name || Account Name || Server Name || Metric Label
    Example: Critical || AcmeCorp || Production || WebServer01 || CPU Utilization
    """

    name = (
        f"{severity} || "
        f"{CLIENT_NAME} || "
        f"{ACCOUNT_NAME} || "
        f"{server_name} || "
        f"{metric_label}"
    )

    return sanitize_alarm_name(name)

# ============================================================
# PUT ALARM (helper)
# ============================================================

def put_alarm(
    alarm_name,
    namespace,
    metric_name,
    dimensions,
    statistic,
    period,
    comparison_operator,
    threshold,
    description
):
    """
    Create or update a single CloudWatch alarm.
    Missing data is treated as breaching (treat missing data = bad).
    """

    logger.info(
        f"  Putting Alarm : {alarm_name}"
    )

    if not SNS_TOPIC_ARN:
        logger.warning(
            "SNS_TOPIC_ARN env var is empty — alarm will be created without notification action"
        )

    alarm_actions = [SNS_TOPIC_ARN] if SNS_TOPIC_ARN else []

    cloudwatch.put_metric_alarm(

        AlarmName=alarm_name,
        AlarmDescription=description,

        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,

        Statistic=statistic,
        Period=period,
        EvaluationPeriods=1,

        ComparisonOperator=comparison_operator,
        Threshold=threshold,
        TreatMissingData="breaching",

        # Trigger ONLY on ALARM state — OK and InsufficientData are silent.
        AlarmActions=alarm_actions,
        OKActions=[],
        InsufficientDataActions=[],

        ActionsEnabled=True,

        Tags=[
            {
                "Key": "Created By",
                "Value": "Monitoring Automation"
            }
        ]
    )

    logger.info(
        f"  Alarm Created/Updated : {alarm_name}"
    )

# ============================================================
# GET DISK DIMENSIONS FOR LINUX
# ============================================================

def get_linux_disk_dimensions(instance_id):
    """
    Query list_metrics to find all disk_used_percent dimension sets
    for this instance. Each mount point is a separate dimension set.
    Returns a list of dimension lists, one per discovered mount/device.
    Falls back to a single InstanceId-only dimension if none found.
    """

    logger.info(
        "  Discovering Linux disk dimensions via list_metrics"
    )

    try:

        response = cloudwatch.list_metrics(
            Namespace="CWAgent",
            MetricName="disk_used_percent",
            Dimensions=[
                {
                    "Name": "InstanceId",
                    "Value": instance_id
                }
            ]
        )

        metrics = response.get("Metrics", [])

        if metrics:

            dimension_sets = []

            for m in metrics:

                dimension_sets.append(m["Dimensions"])

                logger.info(
                    f"  Found disk dimensions : {m['Dimensions']}"
                )

            return dimension_sets

    except Exception as e:

        logger.warning(
            f"  list_metrics for disk failed : {str(e)}"
        )

    # Fallback — alarm on InstanceId only
    logger.info(
        "  No disk dimensions found — using InstanceId fallback"
    )

    return [
        [{"Name": "InstanceId", "Value": instance_id}]
    ]

# ============================================================
# GET DISK DIMENSIONS FOR WINDOWS
# ============================================================

def get_windows_disk_dimensions(instance_id):
    """
    Query list_metrics to find all LogicalDisk % Free Space dimension sets
    for this instance. Each drive letter (C:, D:, etc.) is separate.
    Returns a list of dimension lists, one per discovered drive.
    Falls back to a single InstanceId-only dimension if none found.
    """

    logger.info(
        "  Discovering Windows disk dimensions via list_metrics"
    )

    try:

        response = cloudwatch.list_metrics(
            Namespace="CWAgent",
            MetricName="LogicalDisk % Free Space",
            Dimensions=[
                {
                    "Name": "InstanceId",
                    "Value": instance_id
                }
            ]
        )

        metrics = response.get("Metrics", [])

        # Filter out _Total — we only want real drive letters (C:, D:, etc.)
        real_drives = [
            m for m in metrics
            if not any(
                d["Name"] == "instance" and d["Value"] == "_Total"
                for d in m["Dimensions"]
            )
        ]

        if real_drives:

            dimension_sets = []

            for m in real_drives:

                dimension_sets.append(m["Dimensions"])

                logger.info(
                    f"  Found disk dimensions : {m['Dimensions']}"
                )

            return dimension_sets

    except Exception as e:

        logger.warning(
            f"  list_metrics for Windows disk failed : {str(e)}"
        )

    # Fallback — alarm on InstanceId only
    logger.info(
        "  No Windows disk dimensions found — using InstanceId fallback"
    )

    return [
        [{"Name": "InstanceId", "Value": instance_id}]
    ]

# ============================================================
# CREATE ALERTS
# ============================================================

def create_alerts(instance_id, instance_name, os_type, image_id, instance_type):
    """
    Create all 7 CloudWatch alarms for the given instance.

    Per OS:
      Linux / Ubuntu : CPU x2, Memory (mem_used_percent) x2,
                       Disk (disk_used_percent) x2 per mount, Status x1
      Windows        : CPU x2, Memory (Memory % Committed Bytes In Use) x2,
                       Disk (LogicalDisk % Free Space) x2 per drive, Status x1

    Alarm naming convention:
      Severity || Client Name || Account Name || Server Name || Metric Label
    """

    logger.info(
        "========== CREATING CLOUDWATCH ALERTS =========="
    )

    logger.info(
        f"Instance     : {instance_id}"
    )

    logger.info(
        f"Server Name  : {instance_name}"
    )

    logger.info(
        f"OS Type      : {os_type}"
    )

    logger.info(
        f"Client Name  : {CLIENT_NAME}"
    )

    logger.info(
        f"Account Name : {ACCOUNT_NAME}"
    )

    logger.info(
        f"SNS Topic    : {SNS_TOPIC_ARN or '(not set)'}"
    )

    alarms_created = []
    alarms_failed  = []

    # ----------------------------------------------------------
    # HELPER : create one alarm and track result
    # ----------------------------------------------------------

    def safe_put(
        alarm_name,
        namespace,
        metric_name,
        dimensions,
        statistic,
        period,
        comparison_operator,
        threshold,
        description
    ):
        try:
            put_alarm(
                alarm_name=alarm_name,
                namespace=namespace,
                metric_name=metric_name,
                dimensions=dimensions,
                statistic=statistic,
                period=period,
                comparison_operator=comparison_operator,
                threshold=threshold,
                description=description
            )
            alarms_created.append(alarm_name)

        except Exception as e:
            logger.error(
                f"  FAILED to create alarm [{alarm_name}] : {str(e)}"
            )
            alarms_failed.append(
                {"alarm_name": alarm_name, "error": str(e)}
            )

    # ==========================================================
    # 1. CPU UTILIZATION  (Linux / Ubuntu / Windows — same spec)
    # ==========================================================
    #
    # Namespace : AWS/EC2
    # Metric    : CPUUtilization
    # Statistic : Average
    # Period    : 300 s (5 min)
    # Operator  : GreaterThanOrEqualToThreshold
    # High      : 75 %
    # Critical  : 85 %
    # Missing   : breaching
    # ==========================================================

    logger.info(
        "--- CPU Alerts ---"
    )

    cpu_dimensions = [
        {
            "Name": "InstanceId",
            "Value": instance_id
        }
    ]

    for severity, threshold in [("High", 75), ("Critical", 85)]:

        alarm_name = build_alarm_name(
            severity,
            instance_name,
            "CPU Utilization"
        )

        safe_put(
            alarm_name=alarm_name,
            namespace="AWS/EC2",
            metric_name="CPUUtilization",
            dimensions=cpu_dimensions,
            statistic="Average",
            period=300,
            comparison_operator="GreaterThanOrEqualToThreshold",
            threshold=threshold,
            description=(
                f"{severity} CPU utilization alarm for {instance_name} "
                f"(threshold >= {threshold}%)"
            )
        )

    # ==========================================================
    # 2. MEMORY
    # ==========================================================

    logger.info(
        "--- Memory Alerts ---"
    )

    if os_type == "linux":

        # ------------------------------------------------------
        # Linux / Ubuntu : mem_used_percent  (CWAgent namespace)
        # Namespace : CWAgent
        # Metric    : mem_used_percent
        # Statistic : Average
        # Period    : 300 s (5 min)
        # Operator  : GreaterThanOrEqualToThreshold
        # High      : 75 %
        # Critical  : 85 %
        # Missing   : breaching
        # ------------------------------------------------------

        mem_dimensions = [
            {
                "Name": "InstanceId",
                "Value": instance_id
            }
        ]

        for severity, threshold in [("High", 75), ("Critical", 85)]:

            alarm_name = build_alarm_name(
                severity,
                instance_name,
                "Memory Utilization"
            )

            safe_put(
                alarm_name=alarm_name,
                namespace="CWAgent",
                metric_name="mem_used_percent",
                dimensions=mem_dimensions,
                statistic="Average",
                period=300,
                comparison_operator="GreaterThanOrEqualToThreshold",
                threshold=threshold,
                description=(
                    f"{severity} memory utilization alarm for {instance_name} "
                    f"(threshold >= {threshold}%)"
                )
            )

    else:

        # ------------------------------------------------------
        # Windows : Memory % Committed Bytes In Use  (CWAgent)
        # Namespace : CWAgent
        # Metric    : Memory % Committed Bytes In Use
        # Dimensions: InstanceId + ImageId + InstanceType + objectname
        #             Must match ALL 5 dimensions the CW agent publishes,
        #             otherwise CloudWatch cannot bind to the metric stream.
        # Statistic : Average
        # Period    : 300 s (5 min)
        # Operator  : GreaterThanOrEqualToThreshold
        # High      : 75 %
        # Critical  : 85 %
        # Missing   : breaching
        # ------------------------------------------------------

        mem_dimensions = [
            {
                "Name": "InstanceId",
                "Value": instance_id
            },
            {
                "Name": "ImageId",
                "Value": image_id
            },
            {
                "Name": "InstanceType",
                "Value": instance_type
            },
            {
                "Name": "objectname",
                "Value": "Memory"
            }
        ]

        for severity, threshold in [("High", 75), ("Critical", 85)]:

            alarm_name = build_alarm_name(
                severity,
                instance_name,
                "Memory Utilization"
            )

            safe_put(
                alarm_name=alarm_name,
                namespace="CWAgent",
                metric_name="Memory % Committed Bytes In Use",
                dimensions=mem_dimensions,
                statistic="Average",
                period=300,
                comparison_operator="GreaterThanOrEqualToThreshold",
                threshold=threshold,
                description=(
                    f"{severity} memory utilization alarm for {instance_name} "
                    f"(threshold >= {threshold}%)"
                )
            )

    # ==========================================================
    # 3. DISK
    # ==========================================================

    logger.info(
        "--- Disk Alerts ---"
    )

    if os_type == "linux":

        # ------------------------------------------------------
        # Linux / Ubuntu : disk_used_percent  (CWAgent namespace)
        # Namespace : CWAgent
        # Metric    : disk_used_percent
        # Statistic : Maximum
        # Period    : 60 s (1 min)
        # Operator  : GreaterThanOrEqualToThreshold
        # High      : 75 %
        # Critical  : 85 %
        # Missing   : breaching
        #
        # One alarm per discovered mount point.
        # Dimensions are discovered live from list_metrics so the
        # exact device/fstype/path dimension values are correct.
        # ------------------------------------------------------

        disk_dimension_sets = get_linux_disk_dimensions(instance_id)

        for dim_set in disk_dimension_sets:

            for severity, threshold in [("High", 75), ("Critical", 85)]:

                alarm_name = build_alarm_name(
                    severity,
                    instance_name,
                    "Disk Utilization"
                )

                safe_put(
                    alarm_name=alarm_name,
                    namespace="CWAgent",
                    metric_name="disk_used_percent",
                    dimensions=dim_set,
                    statistic="Maximum",
                    period=60,
                    comparison_operator="GreaterThanOrEqualToThreshold",
                    threshold=threshold,
                    description=(
                        f"{severity} disk utilization alarm for {instance_name} "
                        f"(threshold >= {threshold}%)"
                    )
                )

    else:

        # ------------------------------------------------------
        # Windows : LogicalDisk % Free Space  (CWAgent namespace)
        # Namespace : CWAgent
        # Metric    : LogicalDisk % Free Space
        # Statistic : Maximum
        # Period    : 60 s (1 min)
        # Operator  : LessThanOrEqualToThreshold  (FREE space — lower = worse)
        # High      : 35 % free
        # Critical  : 25 % free
        # Missing   : breaching
        #
        # One alarm per discovered drive (C:, D:, etc.), excluding _Total.
        # Dimensions are discovered live from list_metrics.
        # ------------------------------------------------------

        disk_dimension_sets = get_windows_disk_dimensions(instance_id)

        for dim_set in disk_dimension_sets:

            for severity, threshold in [("High", 35), ("Critical", 25)]:

                alarm_name = build_alarm_name(
                    severity,
                    instance_name,
                    "Disk Utilization"
                )

                safe_put(
                    alarm_name=alarm_name,
                    namespace="CWAgent",
                    metric_name="LogicalDisk % Free Space",
                    dimensions=dim_set,
                    statistic="Maximum",
                    period=60,
                    comparison_operator="LessThanOrEqualToThreshold",
                    threshold=threshold,
                    description=(
                        f"{severity} disk free space alarm for {instance_name} "
                        f"(threshold <= {threshold}% free)"
                    )
                )

    # ==========================================================
    # 4. STATUS CHECK  (Linux / Ubuntu / Windows — same spec)
    # ==========================================================
    #
    # Namespace : AWS/EC2
    # Metric    : StatusCheckFailed
    # Statistic : Maximum
    # Period    : 60 s (1 min)
    # Operator  : GreaterThanOrEqualToThreshold
    # Threshold : 1  (any failure)
    # Severity  : Critical only (single alarm)
    # Missing   : breaching
    # ==========================================================

    logger.info(
        "--- Status Check Alert ---"
    )

    status_dimensions = [
        {
            "Name": "InstanceId",
            "Value": instance_id
        }
    ]

    alarm_name = build_alarm_name(
        "Critical",
        instance_name,
        "Status Check Failed"
    )

    safe_put(
        alarm_name=alarm_name,
        namespace="AWS/EC2",
        metric_name="StatusCheckFailed",
        dimensions=status_dimensions,
        statistic="Maximum",
        period=60,
        comparison_operator="GreaterThanOrEqualToThreshold",
        threshold=1,
        description=(
            f"Critical status check alarm for {instance_name} "
            f"(any EC2 status check failure)"
        )
    )

    # ----------------------------------------------------------
    # SUMMARY
    # ----------------------------------------------------------

    logger.info(
        "========== ALERT CREATION SUMMARY =========="
    )

    logger.info(
        f"Alarms Created : {len(alarms_created)}"
    )

    for name in alarms_created:
        logger.info(
            f"  [OK] {name}"
        )

    if alarms_failed:

        logger.error(
            f"Alarms Failed  : {len(alarms_failed)}"
        )

        for item in alarms_failed:
            logger.error(
                f"  [FAIL] {item['alarm_name']} — {item['error']}"
            )

    return {
        "alarms_created": alarms_created,
        "alarms_failed": alarms_failed
    }

# ============================================================
# MAIN LAMBDA HANDLER
# ============================================================

def lambda_handler(event, context):

    logger.info(
        "========== EVENT RECEIVED =========="
    )

    logger.info(
        json.dumps(event)
    )

    resources = event.get(
        "resources",
        []
    )

    instance_id = None

    for resource in resources:

        if ":instance/" in resource:

            instance_id = (
                resource.split("/")[-1]
            )

            break

    # ========================================================
    # FALLBACK FOR TEST EVENTS
    # ========================================================

    if not instance_id:

        instance_id = event.get("instance_id")

    if not instance_id:

        raise Exception(
            "Instance ID Not Found"
        )

    logger.info(
        f"Instance ID : {instance_id}"
    )

    # ========================================================
    # GET INSTANCE DETAILS
    # ========================================================

    details = get_instance_details(
        instance_id
    )

    # Gracefully skip events for terminated/non-existent instances.
    # EventBridge fires tag-change events even when an instance is
    # deleted (tags become {}). describe_instances returns no results
    # for those; return a skip instead of raising an exception.
    if not details:

        logger.warning(
            f"Instance Not Found : {instance_id} — skipping"
        )

        return {
            "status": "skipped",
            "reason": "Instance not found (terminated or invalid)"
        }

    instance      = details["instance"]
    tags          = details["tags"]
    instance_name = details["instance_name"]
    os_type       = details["os_type"]
    profile_name  = details["profile_name"]
    image_id      = details["image_id"]
    instance_type = details["instance_type"]

    # ========================================================
    # CHECK TAG
    # ========================================================

    monitoring = tags.get(
        "Monitoring",
        ""
    ).strip().lower()

    if monitoring != "yes":

        logger.warning(
            "Monitoring Tag Not Enabled"
        )

        return {
            "status": "skipped",
            "reason": "Monitoring tag not yes"
        }

    # ========================================================
    # VALIDATE INSTANCE — waits until running
    # Returns a refreshed instance object (state may have changed
    # between the initial describe and now, e.g. pending → running)
    # ========================================================

    instance = validate_instance(instance_id)

    logger.info(
        f"Instance Name : {instance_name}"
    )

    logger.info(
        f"Detected OS : {os_type}"
    )

    # ========================================================
    # ENABLE EC2 DETAILED MONITORING
    # ========================================================

    enable_detailed_monitoring(
        instance_id
    )

    # ========================================================
    # ENSURE IAM ROLE
    # ========================================================

    role_name = ensure_role_setup(
        instance_id,
        instance_name,
        profile_name
    )

    # ========================================================
    # WAIT FOR SSM ONLINE
    # ========================================================

    wait_for_ssm(instance_id)

    # ========================================================
    # INSTALL CW AGENT
    # ========================================================

    install_cloudwatch_agent(
        instance_id,
        os_type
    )

    # ========================================================
    # CONFIGURE CW AGENT
    # ========================================================

    configure_cloudwatch_agent(
        instance_id,
        os_type
    )

    # ========================================================
    # VERIFY METRICS
    # ========================================================

    metrics_working = verify_metrics(
        instance_id,
        os_type
    )

    # ========================================================
    # CREATE CLOUDWATCH ALERTS
    # (runs after metrics are confirmed flowing)
    # ========================================================

    alert_result = create_alerts(
        instance_id,
        instance_name,
        os_type,
        image_id,
        instance_type
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    result = {

        "status": "success",

        "instance_id": instance_id,

        "instance_name": instance_name,

        "os_type": os_type,

        "iam_role_name": role_name,

        "metrics_flowing": metrics_working,

        "alarms_created": alert_result["alarms_created"],

        "alarms_failed": alert_result["alarms_failed"]
    }

    logger.info(
        "========== FINAL RESULT =========="
    )

    logger.info(
        json.dumps(result, indent=4)
    )

    return result