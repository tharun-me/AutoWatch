import boto3
import json
import os
import urllib.parse
import logging

from datetime import datetime, timezone, timedelta

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ─────────────────────────────────────────────
# AWS / ENV CONFIG
# ─────────────────────────────────────────────

REGION = os.environ.get("AWS_REGION", "ap-south-1")

SES_SENDER = os.environ.get("SES_SENDER")

SES_RECIPIENTS = [
    x.strip()
    for x in os.environ.get("SES_RECIPIENTS", "").split(",")
    if x.strip()
]

# New: client identity passed via Lambda env vars
CLIENT_NAME  = os.environ.get("CLIENT_NAME",  "N/A")
ACCOUNT_NAME = os.environ.get("ACCOUNT_NAME", "N/A")

# ─────────────────────────────────────────────
# AWS CLIENTS
# ─────────────────────────────────────────────

ses = boto3.client("ses",          region_name=REGION)
ec2 = boto3.client("ec2",          region_name=REGION)
cw  = boto3.client("cloudwatch",   region_name=REGION)

IST = timezone(timedelta(hours=5, minutes=30))

# ─────────────────────────────────────────────
# SEVERITY STYLES
# ─────────────────────────────────────────────

SEVERITY_CONFIG = {
    "Critical": {
        "bg":     "#fef2f2",
        "border": "#fee2e2",
        "text":   "#dc2626",
        "value":  "#dc2626",
        "button": "#991b1b",
    },
    "High": {
        "bg":     "#fff7ed",
        "border": "#fed7aa",
        "text":   "#ea580c",
        "value":  "#ea580c",
        "button": "#9a3412",
    },
    "Warning": {
        "bg":     "#fefce8",
        "border": "#fde68a",
        "text":   "#ca8a04",
        "value":  "#ca8a04",
        "button": "#854d0e",
    },
}

# ─────────────────────────────────────────────
# METRIC LABEL MAP  (used in subject line)
# ─────────────────────────────────────────────

METRIC_LABEL_MAP = {
    "cpuutilization":                      "CPU Utilization",
    "memory % committed bytes in use":     "Memory Utilization",
    "logicaldisk % free space":            "Disk Utilization",
    "statuscheckfailed":                   "Status Check",
    "statuscheckfailed_instance":          "Instance Status Check",
    "statuscheckfailed_system":            "System Status Check",
    "networkout":                          "Network Out",
    "networkin":                           "Network In",
    "diskreadops":                         "Disk Read IOPS",
    "diskwriteops":                        "Disk Write IOPS",
}


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def safe(value):
    if value is None:
        return "N/A"
    return str(value)


def format_time(iso_time):
    try:
        dt = datetime.strptime(
            iso_time[:19], "%Y-%m-%dT%H:%M:%S"
        ).replace(tzinfo=timezone.utc)
        return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        return safe(iso_time)


def get_metric_label(metric_name: str) -> str:
    """Return a human-friendly label for the metric (used in subject)."""
    lower = metric_name.lower()
    for key, label in METRIC_LABEL_MAP.items():
        if key in lower:
            return label
    return metric_name


def detect_severity(alarm_name: str) -> str:
    """
    Parse severity from the alarm name prefix  e.g.
      'Critical || PandOps || MES_Prod || ...'  → 'Critical'
      'High || ...'                              → 'High'
    Falls back to keyword scan if prefix not recognised.
    """
    parts = [p.strip() for p in alarm_name.split("||")]
    if parts:
        candidate = parts[0].title()
        if candidate in SEVERITY_CONFIG:
            logger.info(f"[SEVERITY] Parsed from alarm name prefix: {candidate}")
            return candidate

    # Keyword fallback
    text = alarm_name.lower()
    if "critical" in text:
        sev = "Critical"
    elif "warning" in text:
        sev = "Warning"
    else:
        sev = "High"

    logger.info(f"[SEVERITY] Fallback keyword detection: {sev}")
    return sev


def get_cloudwatch_url(alarm_name: str) -> str:
    encoded = urllib.parse.quote(alarm_name, safe="")
    return (
        f"https://{REGION}.console.aws.amazon.com/"
        f"cloudwatch/home?region={REGION}"
        f"#alarmsV2:alarm/{encoded}"
    )


def build_description(metric_name: str, server_name: str) -> str:
    """Generate a human-readable description matching the required HTML format."""
    lower = metric_name.lower()

    if "cpu" in lower:
        detail = "sustained high CPU utilization"
    elif "memory" in lower:
        detail = "sustained high memory utilization"
    elif "disk" in lower or "logicaldisk" in lower:
        detail = "low logical disk free space"
    elif "statuscheck" in lower:
        detail = "a status check failure"
    elif "networkin" in lower:
        detail = "high inbound network traffic"
    elif "networkout" in lower:
        detail = "high outbound network traffic"
    else:
        detail = f"a threshold breach on <em>{metric_name}</em>"

    return (
        f"The server <strong style=\"color:#0f172a;\">{server_name}</strong> "
        f"has reported {detail} for more than 5 minutes. "
        f"Take necessary action for this alert or change the threshold or silence this alert."
    )


def build_subject(
    severity: str,
    server_name: str,
    metric_name: str,
) -> str:
    """
    Format: Severity || ClientName || AccountName || ServerName || Metric Label
    ClientName and AccountName come from Lambda env vars CLIENT_NAME / ACCOUNT_NAME.
    """
    label = get_metric_label(metric_name)
    subject = (
        f"{severity} || {CLIENT_NAME} || {ACCOUNT_NAME} "
        f"|| {server_name} || {label}"
    )
    logger.info(f"[SUBJECT] Built email subject: {subject}")
    return subject


# ─────────────────────────────────────────────
# FETCH EC2 DETAILS
# ─────────────────────────────────────────────

def fetch_ec2_details(instance_id: str) -> dict:
    logger.info(f"[EC2] Fetching details for instance_id={instance_id}")

    if instance_id == "N/A":
        logger.warning("[EC2] No instance_id available — skipping describe_instances.")
        return {
            "instance_id": instance_id,
            "server_name": "N/A",
            "private_ip": "N/A",
            "instance_type": "N/A",
            "platform": "N/A",
            "instance_state": "unknown",
            "tags": {},
        }

    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]

        tags = {
            t["Key"]: t["Value"]
            for t in instance.get("Tags", [])
        }

        state      = instance.get("State", {}).get("Name", "unknown")
        name       = tags.get("Name", instance_id)
        private_ip = instance.get("PrivateIpAddress", "N/A")
        itype      = instance.get("InstanceType", "N/A")
        platform   = instance.get("PlatformDetails", "Linux/UNIX")

        logger.info(
            f"[EC2] Success — name={name} | state={state} | "
            f"type={itype} | ip={private_ip} | platform={platform}"
        )
        logger.info(f"[EC2] Tags found: {json.dumps(tags)}")

        return {
            "instance_id":    instance_id,
            "server_name":    name,
            "private_ip":     private_ip,
            "instance_type":  itype,
            "platform":       platform,
            "instance_state": state,
            "tags":           tags,
        }

    except Exception as e:
        logger.error(f"[EC2] describe_instances FAILED for {instance_id}: {e}", exc_info=True)
        return {
            "instance_id":    instance_id,
            "server_name":    instance_id,
            "private_ip":     "N/A",
            "instance_type":  "N/A",
            "platform":       "N/A",
            "instance_state": "unknown",
            "tags":           {},
        }


# ─────────────────────────────────────────────
# FETCH METRIC VALUE
# ─────────────────────────────────────────────

def fetch_metric_value(
    namespace: str,
    metric_name: str,
    trigger_dimensions: list,
) -> tuple[str | None, list]:
    """
    Returns (formatted_value_or_None, raw_datapoints).
    Uses the exact dimensions from the CloudWatch trigger so that
    CWAgent metrics (Memory, LogicalDisk, etc.) work correctly.
    """

    # Build dim list exactly as CloudWatch sent them
    dim_list = [
        {"Name": d["name"], "Value": d["value"]}
        for d in trigger_dimensions
    ]

    logger.info(
        f"[METRIC] Fetching  namespace={namespace}  metric={metric_name}  "
        f"dimensions={json.dumps(dim_list)}"
    )

    try:
        now   = datetime.now(timezone.utc)
        start = now - timedelta(minutes=15)

        response = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=dim_list,
            StartTime=start,
            EndTime=now,
            Period=300,
            Statistics=["Average"],
        )

        datapoints = response.get("Datapoints", [])
        logger.info(
            f"[METRIC] Response received — datapoints_count={len(datapoints)}"
        )

        if datapoints:
            sorted_dp = sorted(datapoints, key=lambda x: x["Timestamp"])
            latest    = sorted_dp[-1]
            avg       = latest["Average"]
            ts        = latest["Timestamp"].strftime("%Y-%m-%dT%H:%M:%SZ")

            logger.info(
                f"[METRIC] Latest datapoint — timestamp={ts}  average={avg:.4f}"
            )

            lower = metric_name.lower()
            if "statuscheckfailed" in lower:
                # CloudWatch returns 0 (passing) or 1 (failing)
                formatted = "FAILED" if avg >= 1 else "OK"
                logger.info(
                    f"[METRIC] StatusCheck raw avg={avg:.4f} → formatted={formatted}"
                )
            elif any(k in lower for k in ["percent", "utilization", "cpu", "% free", "% committed"]):
                formatted = f"{avg:.2f}%"
            else:
                formatted = f"{avg:.2f}"

            logger.info(f"[METRIC] Formatted value: {formatted}")
            return formatted, datapoints

        else:
            logger.warning(
                f"[METRIC] No datapoints returned for {metric_name} "
                f"in the last 15 minutes."
            )
            return None, []

    except Exception as e:
        logger.error(
            f"[METRIC] get_metric_statistics FAILED — namespace={namespace}  "
            f"metric={metric_name}  error={e}",
            exc_info=True,
        )
        return None, []


# ─────────────────────────────────────────────
# DETECT ALARM ISSUE  (when no metric data)
# ─────────────────────────────────────────────

def detect_alarm_issue(
    metric_name: str,
    new_state: str,
    ec2_info: dict,
    datapoints: list,
) -> str:
    instance_state = ec2_info.get("instance_state", "unknown").lower()
    metric_lower   = metric_name.lower()

    logger.info(
        f"[ISSUE] Detecting issue — metric={metric_name}  "
        f"new_state={new_state}  instance_state={instance_state}  "
        f"datapoints_count={len(datapoints)}"
    )

    if instance_state in ["stopped", "stopping", "terminated"]:
        issue = "INSTANCE STOPPED"
    elif "statuscheckfailed" in metric_lower:
        issue = "STATUS CHECK FAILED"
    elif new_state == "ALARM" and not datapoints:
        issue = "BREACHED — NO DATA"
    elif new_state == "INSUFFICIENT_DATA":
        issue = "INSUFFICIENT DATA"
    else:
        issue = "NO METRIC DATA"

    logger.info(f"[ISSUE] Resolved issue label: {issue}")
    return issue


# ─────────────────────────────────────────────
# TAGS HTML
# ─────────────────────────────────────────────

def build_tags_html(tags: dict) -> str:
    if not tags:
        return (
            '<div style="color:#64748b;font-size:13px;">No Tags Found</div>'
        )

    colors = [
        ("#eff6ff", "#1d4ed8", "#bfdbfe"),
        ("#f5f3ff", "#6d28d9", "#ddd6fe"),
        ("#ecfeff", "#0891b2", "#a5f3fc"),
        ("#fef2f2", "#dc2626", "#fecaca"),
        ("#ecfccb", "#4d7c0f", "#d9f99d"),
    ]

    html = ""
    for idx, (k, v) in enumerate(tags.items()):
        bg, text, border = colors[idx % len(colors)]
        html += (
            f'<span style="display:inline-block;background:{bg};color:{text};'
            f'border:1px solid {border};border-radius:999px;padding:8px 12px;'
            f'font-size:12px;font-weight:700;margin:4px;">'
            f"{safe(k)}: {safe(v)}"
            f"</span>"
        )

    return html


# ─────────────────────────────────────────────
# BUILD METRIC VALUE HTML BLOCK
# ─────────────────────────────────────────────

def build_metric_value_html(
    metric_value: str | None,
    alarm_issue: str | None,
    style: dict,
) -> str:
    """
    Returns the HTML for the 'Current Value' table cell.
    - When we have a real numeric value  → large coloured number.
    - When we only have an issue label   → small styled badge (no giant text).
    """
    if metric_value is not None:
        return (
            f'<div style="font-size:34px;color:{style["value"]};'
            f'font-weight:900;line-height:1;">'
            f"{metric_value}"
            f"</div>"
        )

    label = alarm_issue or "N/A"
    return (
        f'<span style="display:inline-block;'
        f'background:{style["bg"]};'
        f'border:1px solid {style["border"]};'
        f'color:{style["text"]};'
        f'padding:8px 14px;border-radius:8px;'
        f'font-size:12px;font-weight:800;'
        f'letter-spacing:0.5px;">'
        f"{label}"
        f"</span>"
    )


# ─────────────────────────────────────────────
# HTML TEMPLATE
# ─────────────────────────────────────────────

def build_html(
    severity,
    style,
    alert_time,
    metric_name,
    alarm_name,
    description,
    ec2_info,
    metric_value_html,
    alarm_issue,
    cw_url,
):
    tags_html = build_tags_html(ec2_info["tags"])

    # Show alarm_issue badge only when there's a real issue to report
    issue_badge_html = ""
    if alarm_issue:
        issue_badge_html = (
            f'<div style="display:inline-block;'
            f'background:{style["bg"]};'
            f'border:1px solid {style["border"]};'
            f'color:{style["text"]};'
            f'padding:10px 16px;border-radius:999px;'
            f'font-size:13px;font-weight:800;margin-bottom:24px;">'
            f"{alarm_issue}"
            f"</div>"
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shellkode Alert</title>
</head>
<body style="margin:0;padding:0;background:#eef2f7;font-family:'Segoe UI',Arial,sans-serif;">

<table width="100%" cellpadding="0" cellspacing="0" border="0"
  style="padding:32px 12px;background:#eef2f7;">
<tr><td align="center">

<table width="680" cellpadding="0" cellspacing="0" border="0"
  style="max-width:680px;width:100%;border-radius:16px;overflow:hidden;
         background:#ffffff;box-shadow:0 8px 30px rgba(15,23,42,0.08);">

<!-- ── HEADER ── -->
<tr>
<td style="padding:16px 34px;
  background:radial-gradient(circle at top right,rgba(59,130,246,0.10),transparent 30%),
             linear-gradient(135deg,#f8fbff 0%,#eef4ff 55%,#e7f0ff 100%);
  border-bottom:1px solid #dbeafe;">

  <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>

    <td valign="middle">
      <img src="https://rajinithalaivarda.s3.ap-south-1.amazonaws.com/Logo_crop.png"
        alt="Shellkode"
        style="display:block;height:58px;width:auto;max-width:240px;">
    </td>

    <td align="right" valign="middle">
      <div style="display:inline-block;padding:10px 22px;background:#ffffff;
        border:1px solid #dbeafe;border-radius:999px;color:#2563eb;
        font-size:11px;font-weight:800;letter-spacing:1.8px;text-transform:uppercase;">
        Cloud Monitoring
      </div>
    </td>

  </tr></table>
</td>
</tr>

<!-- ── ALERT STRIP ── -->
<tr>
<td style="background-color:{style['bg']};padding:12px 40px;
           border-bottom:1px solid {style['border']};">
  <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>

    <td align="left" valign="middle"
      style="color:{style['text']};font-size:13px;font-weight:700;
             letter-spacing:0.5px;text-transform:uppercase;">
      <span style="color:{style['text']};margin-right:6px;">●</span>
      {severity} Alert
    </td>

    <td align="right" valign="middle"
      style="color:#64748b;font-size:13px;font-weight:500;">
      {alert_time}
    </td>

  </tr></table>
</td>
</tr>

<!-- ── MAIN ── -->
<tr>
<td style="padding:38px 36px;">

  <!-- TITLE -->
  <div style="font-size:26px;line-height:1.3;font-weight:800;
              color:#0f172a;margin-bottom:10px;">
    {metric_name} — {ec2_info['server_name']}
  </div>

  <!-- DESCRIPTION -->
  <div style="font-size:14px;line-height:1.8;color:#64748b;margin-bottom:30px;">
    {description}
  </div>

  <!-- ISSUE BADGE (only when no real metric value) -->
  {issue_badge_html}

  <!-- METRIC CARD -->
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
    style="background:#f8fafc;border:1px solid #e2e8f0;
           border-radius:12px;margin-bottom:30px;">
  <tr><td style="padding:24px;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0">

      <!-- Row 1: Client | AWS Account -->
      <tr>
        <td width="50%" style="padding-bottom:20px;">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            Client
          </div>
          <div style="font-size:16px;color:#0f172a;font-weight:700;">
            {CLIENT_NAME}
          </div>
        </td>
        <td width="50%" style="padding-bottom:20px;">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            AWS Account
          </div>
          <div style="font-size:16px;color:#0f172a;font-weight:700;">
            {ACCOUNT_NAME}
          </div>
        </td>
      </tr>

      <!-- Row 2: Instance Name | Instance ID -->
      <tr>
        <td width="50%" style="padding-bottom:20px;">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            Instance
          </div>
          <div style="font-size:16px;color:#0f172a;font-weight:700;">
            {ec2_info['server_name']}
          </div>
        </td>
        <td width="50%" style="padding-bottom:20px;">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            Instance ID
          </div>
          <div style="font-size:15px;color:#0f172a;font-family:monospace;font-weight:700;">
            {ec2_info['instance_id']}
          </div>
        </td>
      </tr>

      <!-- Row 3: Metric Name | Current Value -->
      <tr>
        <td width="50%">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            Metric
          </div>
          <div style="font-size:16px;color:#0f172a;font-weight:700;">
            {metric_name}
          </div>
        </td>
        <td width="50%">
          <div style="font-size:11px;color:#94a3b8;font-weight:700;
                      letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px;">
            Current Value
          </div>
          {metric_value_html}
        </td>
      </tr>

    </table>
  </td></tr>
  </table>

  <!-- TAGS -->
  <div style="font-size:11px;color:#94a3b8;font-weight:700;
              letter-spacing:1.5px;text-transform:uppercase;margin-bottom:14px;">
    Resource Tags
  </div>
  <table width="100%" cellpadding="0" cellspacing="0" border="0"
    style="margin-bottom:34px;">
  <tr>
    <td style="background:#ffffff;border:1px solid #e2e8f0;
               border-radius:12px;padding:18px;">
      <div>{tags_html}</div>
    </td>
  </tr>
  </table>

  <!-- BUTTON -->
  <table cellpadding="0" cellspacing="0" border="0">
  <tr>
    <td style="border-radius:10px;background:{style['button']};">
      <a href="{cw_url}"
        style="display:inline-block;padding:16px 28px;color:#ffffff;
               text-decoration:none;font-size:14px;font-weight:700;
               letter-spacing:0.3px;">
        Open CloudWatch Dashboard →
      </a>
    </td>
  </tr>
  </table>

</td>
</tr>

<!-- ── FOOTER ── -->
<tr>
<td style="padding:24px 36px;background:#0b1220;
           border-top:1px solid rgba(255,255,255,0.05);">
  <table width="100%" cellpadding="0" cellspacing="0" border="0"><tr>

    <td>
      <div style="color:#dbeafe;font-size:13px;font-weight:700;margin-bottom:6px;">
        Shellkode Managed Services Providers
      </div>
      <div style="color:#64748b;font-size:11px;line-height:1.7;">
        Automated infrastructure alert generated by Shellkode Monitoring Platform.
      </div>
    </td>

    <td align="right">
      <div style="color:#475569;font-size:11px;">© 2026 Shellkode</div>
    </td>

  </tr></table>
</td>
</tr>

</table>
</td></tr>
</table>
</body>
</html>"""


# ─────────────────────────────────────────────
# LAMBDA HANDLER
# ─────────────────────────────────────────────

def lambda_handler(event, context):

    logger.info("=" * 60)
    logger.info("[HANDLER] Lambda invoked — processing SNS event")
    logger.info(f"[HANDLER] Raw event: {json.dumps(event)}")
    logger.info("=" * 60)

    records = event.get("Records", [])
    logger.info(f"[HANDLER] Total SNS records to process: {len(records)}")

    for idx, record in enumerate(records):
        logger.info(f"[HANDLER] ── Processing record {idx + 1}/{len(records)} ──")

        try:
            # ── Parse SNS wrapper ──────────────────────────────
            sns_wrapper = record.get("Sns", {})
            message_id  = sns_wrapper.get("MessageId", "N/A")
            topic_arn   = sns_wrapper.get("TopicArn",  "N/A")
            raw_message = sns_wrapper.get("Message",   "{}")

            logger.info(f"[SNS] MessageId={message_id}  TopicArn={topic_arn}")
            logger.info(f"[SNS] Raw Message string: {raw_message}")

            sns_message = json.loads(raw_message)
            logger.info(f"[SNS] Parsed Message JSON: {json.dumps(sns_message, default=str)}")

            # ── Extract alarm fields ────────────────────────────
            alarm_name  = sns_message.get("AlarmName",        "Unknown Alarm")
            description_raw = sns_message.get("AlarmDescription", "")
            new_state   = sns_message.get("NewStateValue",    "UNKNOWN")
            old_state   = sns_message.get("OldStateValue",    "UNKNOWN")
            state_reason = sns_message.get("NewStateReason",  "No reason provided.")
            state_time  = sns_message.get("StateChangeTime",  "")
            aws_account = sns_message.get("AWSAccountId",     "N/A")

            logger.info(
                f"[ALARM] Name={alarm_name}  "
                f"OldState={old_state} → NewState={new_state}"
            )
            logger.info(f"[ALARM] StateChangeTime={state_time}")
            logger.info(f"[ALARM] StateReason={state_reason}")
            logger.info(f"[ALARM] AWSAccountId={aws_account}")

            # ── Extract trigger / dimensions ────────────────────
            trigger     = sns_message.get("Trigger", {})
            metric_name = trigger.get("MetricName", "Unknown Metric")
            namespace   = trigger.get("Namespace",  "AWS/EC2")
            period      = trigger.get("Period",      300)
            threshold   = trigger.get("Threshold",   "N/A")
            treat_miss  = trigger.get("TreatMissingData", "N/A")
            eval_periods = trigger.get("EvaluationPeriods", 1)
            raw_dims    = trigger.get("Dimensions", [])

            logger.info(
                f"[TRIGGER] Metric={metric_name}  Namespace={namespace}  "
                f"Period={period}s  Threshold={threshold}  "
                f"EvalPeriods={eval_periods}  TreatMissing={treat_miss}"
            )
            logger.info(f"[TRIGGER] Raw dimensions: {json.dumps(raw_dims)}")

            # ── Extract InstanceId from dimensions ──────────────
            dim_map = {d["name"]: d["value"] for d in raw_dims}
            instance_id = (
                dim_map.get("InstanceId")
                or dim_map.get("instanceId")
                or "N/A"
            )
            logger.info(f"[TRIGGER] InstanceId resolved: {instance_id}")

            # ── Severity ───────────────────────────────────────
            severity = detect_severity(alarm_name)
            style    = SEVERITY_CONFIG[severity]
            logger.info(f"[SEVERITY] Final severity: {severity}")

            # ── Format alert time ──────────────────────────────
            alert_time = format_time(state_time)
            logger.info(f"[TIME] Alert time (IST): {alert_time}")

            # ── EC2 details ────────────────────────────────────
            ec2_info = fetch_ec2_details(instance_id)

            # ── Metric value fetch ─────────────────────────────
            logger.info(
                f"[METRIC] Starting metric fetch — "
                f"namespace={namespace}  metric={metric_name}  "
                f"dims={json.dumps(raw_dims)}"
            )
            metric_value, datapoints = fetch_metric_value(
                namespace=namespace,
                metric_name=metric_name,
                trigger_dimensions=raw_dims,
            )

            # ── Alarm issue detection ──────────────────────────
            alarm_issue = None
            if metric_value is None:
                alarm_issue = detect_alarm_issue(
                    metric_name=metric_name,
                    new_state=new_state,
                    ec2_info=ec2_info,
                    datapoints=datapoints,
                )
                logger.info(f"[ISSUE] No numeric value — alarm_issue={alarm_issue}")
            else:
                logger.info(f"[METRIC] Using numeric value: {metric_value}")

            # ── Build HTML metric value block ──────────────────
            metric_value_html = build_metric_value_html(
                metric_value=metric_value,
                alarm_issue=alarm_issue,
                style=style,
            )
            logger.info(f"[HTML] metric_value_html length={len(metric_value_html)}")

            # ── Description ────────────────────────────────────
            server_name = ec2_info["server_name"]
            description = build_description(metric_name, server_name)
            logger.info(f"[DESCRIPTION] Generated: {description[:120]}...")

            # ── CloudWatch URL ─────────────────────────────────
            cw_url = get_cloudwatch_url(alarm_name)
            logger.info(f"[URL] CloudWatch dashboard: {cw_url}")

            # ── Subject ────────────────────────────────────────
            subject = build_subject(
                severity=severity,
                server_name=server_name,
                metric_name=metric_name,
            )

            # ── Build full HTML ────────────────────────────────
            logger.info("[HTML] Building email HTML body...")
            html_body = build_html(
                severity=severity,
                style=style,
                alert_time=alert_time,
                metric_name=metric_name,
                alarm_name=alarm_name,
                description=description,
                ec2_info=ec2_info,
                metric_value_html=metric_value_html,
                alarm_issue=alarm_issue,
                cw_url=cw_url,
            )
            logger.info(f"[HTML] Email body built — total_chars={len(html_body)}")

            # ── SES send ───────────────────────────────────────
            logger.info(
                f"[SES] Sending email — "
                f"From={SES_SENDER}  To={SES_RECIPIENTS}  Subject={subject}"
            )

            response = ses.send_email(
                Source=SES_SENDER,
                Destination={"ToAddresses": SES_RECIPIENTS},
                Message={
                    "Subject": {"Data": subject},
                    "Body":    {"Html": {"Data": html_body}},
                },
            )

            ses_msg_id = response.get("MessageId", "N/A")
            logger.info(f"[SES] Email sent successfully — SES MessageId={ses_msg_id}")
            logger.info(f"[HANDLER] Record {idx + 1} processed successfully ✓")

        except Exception as e:
            logger.error(
                f"[HANDLER] FAILED on record {idx + 1}: {e}",
                exc_info=True,
            )

    logger.info(f"[HANDLER] All {len(records)} record(s) processed — Lambda complete.")
    return {"statusCode": 200, "body": "HTML SES Alerts Sent"}