# 📡 AutoWatch (Serverless)

A fully automated, serverless AWS monitoring solution that installs, configures, and manages CloudWatch monitoring for EC2 instances while sending beautifully formatted HTML email alerts.

The solution is designed to:

* Automatically onboard EC2 instances into monitoring
* Install and configure CloudWatch Agent
* Create standardized CloudWatch alarms
* Send rich HTML email alerts using Amazon SES
* Support both Linux and Windows instances
* Be fully automated with minimal manual intervention

No SSH. No RDP. No manual CloudWatch configuration.

---

# 🚀 What This Project Does

This project consists of **two AWS Lambda functions** working together.

## Lambda 1 — Monitoring Automation

Automatically prepares every EC2 instance for monitoring.

It performs the following:

* Detects newly tagged or onboarded EC2 instances
* Creates IAM Roles if required
* Attaches required IAM policies
* Creates/Attaches Instance Profiles
* Waits for SSM availability
* Installs Amazon CloudWatch Agent
* Configures CloudWatch Agent
* Enables Detailed Monitoring
* Verifies metrics are publishing
* Creates CloudWatch alarms
* Configures SNS notifications

---

## Lambda 2 — Alert Enrichment & Notification

When a CloudWatch Alarm is triggered:

* Receives the SNS notification
* Retrieves EC2 details
* Fetches the latest metric value
* Detects alarm severity
* Detects monitoring issues
* Builds a professional HTML email
* Sends the notification using Amazon SES

Instead of AWS's default plain-text emails, recipients receive a rich monitoring dashboard directly in their inbox.

---

# 🧠 Monitoring Features

The solution automatically monitors:

### EC2 Native Metrics

* CPU Utilization
* Status Check Failed
* Instance Status Check
* System Status Check
* Network In
* Network Out
* Disk Read Operations
* Disk Write Operations

---

### CloudWatch Agent Metrics

## Linux

* Memory Utilization
* Disk Usage %

---

## Windows

* Memory Utilization
* Logical Disk Free %
* Logical Disk Free MB

---

# 🚨 Alarm Severity

The project supports standardized alert severities.

```
Critical

High

Warning
```

Each severity has

* Different colors
* Email styling
* Subject formatting
* Alert banners

making alerts immediately recognizable.

---

# 🏗 Architecture

```
                EC2 Instance
                     │
                     ▼
            EventBridge / Trigger
                     │
                     ▼
       Lambda 1 - Monitoring Automation
                     │
                     ▼
              IAM Role / Profile
                     │
                     ▼
                    SSM
                     │
                     ▼
      Install CloudWatch Agent
                     │
                     ▼
      Configure CloudWatch Agent
                     │
                     ▼
        Publish CloudWatch Metrics
                     │
                     ▼
       Create CloudWatch Alarms
                     │
                     ▼
                  SNS Topic
                     │
                     ▼
      Lambda 2 - Alert Enrichment
                     │
                     ▼
            Fetch EC2 Details
                     │
                     ▼
          Generate HTML Email
                     │
                     ▼
                 Amazon SES
                     │
                     ▼
                  End Users
```

---

# ✨ Key Characteristics

✅ Fully Serverless

✅ Zero Manual EC2 Configuration

✅ Linux & Windows Support

✅ Automatic IAM Role Creation

✅ Automatic CloudWatch Agent Installation

✅ Automatic Alarm Creation

✅ Professional HTML Email Alerts

✅ Multi-Environment Ready

✅ Production Friendly

---

# 📦 AWS Resources Used

The solution integrates with:

* AWS Lambda
* Amazon EC2
* AWS Systems Manager (SSM)
* Amazon CloudWatch
* Amazon CloudWatch Agent
* Amazon SNS
* Amazon SES
* AWS IAM
* Amazon EventBridge

---

# 🔔 CloudWatch Alarms Created

Typical alarms include:

## Critical

* CPU Utilization
* Memory Utilization
* Status Check Failed

---

## High

* Network Traffic
* Disk Operations

---

## Warning

* Disk Free Space
* Resource Thresholds

Alarm thresholds can easily be customized.

---

# 📧 Professional Email Alerts

Unlike default CloudWatch emails, this project sends fully branded HTML notifications.

Each email contains:

* Company Logo
* Client Name
* AWS Account
* Instance Name
* Instance ID
* Metric Name
* Current Metric Value
* Severity Banner
* Resource Tags
* Alert Description
* Direct CloudWatch Alarm Link
* Alert Timestamp

This makes alerts much easier for operations teams to understand and act upon.

---

# ⚙ Environment Variables

## Monitoring Lambda

| Variable      | Description                       |
| ------------- | --------------------------------- |
| SNS_TOPIC_ARN | SNS Topic for alarm notifications |
| CLIENT_NAME   | Client name                       |
| ACCOUNT_NAME  | Friendly AWS account name         |

---

## Alert Lambda

| Variable       | Description                        |
| -------------- | ---------------------------------- |
| SES_SENDER     | Verified SES sender email          |
| SES_RECIPIENTS | Email recipients (comma separated) |
| CLIENT_NAME    | Client name                        |
| ACCOUNT_NAME   | Friendly AWS account               |
| AWS_REGION     | Deployment region                  |

---

# 🔐 IAM Permissions Used

## Monitoring Lambda

Requires permissions for:

```
EC2

IAM

SSM

CloudWatch

SNS

CloudWatch Agent
```

Including actions such as:

* DescribeInstances
* MonitorInstances
* AssociateIamInstanceProfile
* CreateRole
* AttachRolePolicy
* SendCommand
* PutMetricAlarm
* ListMetrics

---

## Alert Lambda

Requires permissions for:

* CloudWatch Read
* EC2 Describe
* SES Send Email

---

# 🛠 Deployment Overview

## Step 1

Deploy the Monitoring Automation Lambda.

---

## Step 2

Deploy the Alert Enrichment Lambda.

---

## Step 3

Create an SNS Topic.

---

## Step 4

Subscribe the Alert Lambda to the SNS Topic.

---

## Step 5

Configure CloudWatch Alarms to publish to the SNS Topic.

---

## Step 6

Configure Amazon SES.

* Verify sender email
* Verify recipients (if SES Sandbox)
* Set environment variables

---

## Step 7

Tag or register EC2 instances according to your onboarding process.

The automation will:

* Configure IAM
* Install CloudWatch Agent
* Publish Metrics
* Create Alarms

automatically.

---

# 🔄 Monitoring Workflow

```
New EC2 Instance

↓

Monitoring Lambda

↓

Create IAM Role

↓

Attach IAM Profile

↓

Wait for SSM

↓

Install CloudWatch Agent

↓

Configure Agent

↓

Verify Metrics

↓

Enable Detailed Monitoring

↓

Create CloudWatch Alarms

↓

Alarm Triggered

↓

SNS

↓

Alert Lambda

↓

Fetch Metric Value

↓

Generate HTML Email

↓

SES

↓

Operations Team
```

---

# 📈 Use Cases

* Managed Service Providers (MSPs)
* Enterprise Cloud Operations
* Infrastructure Monitoring
* Production AWS Environments
* Internal DevOps Teams
* Customer Managed AWS Accounts
* Cloud Operations Centers (NOC)
* Multi-Client Monitoring

---

# 🛣 Roadmap

## 🔵 v1.0 (Current)

* Automatic CloudWatch Agent installation
* Automatic IAM configuration
* Automatic CloudWatch alarms
* HTML Email Alerts
* Linux Support
* Windows Support
* SES Integration
* SNS Integration

---

## 🟢 v1.1 (Planned)

* Alarm threshold customization
* CloudWatch Dashboard creation
* Alarm suppression
* Maintenance window support
* Auto-remediation hooks

---

## 🟡 v2.0 (Planned)

* Multi-Account Monitoring
* AWS Organizations support
* Cross-Region aggregation
* Auto-discovery
* Auto-healing actions
* Slack Integration
* Microsoft Teams Integration

---

## 🔴 v3.0 (Long-Term)

* Web Dashboard
* Historical Alert Analytics
* Cost-aware Monitoring
* AI-based Alert Correlation
* Terraform Module
* AWS Marketplace Package

---

# 🤝 Contributing

Contributions, feature requests, bug reports, and ideas are always welcome.

The project is intentionally designed to be:

* Easy to deploy
* Easy to understand
* Easy to extend
* Enterprise ready

---

# 📜 License

MIT License

Feel free to use, modify, distribute, and extend this project for personal, commercial, or enterprise environments.

---

# ⭐ Project Highlights

* 🚀 Fully Automated Cloud Monitoring
* ☁ AWS Native Architecture
* 📡 Zero Manual CloudWatch Setup
* 🖥 Windows & Linux Support
* 📧 Beautiful HTML Email Alerts
* 🔒 Security Best Practices
* ⚡ Serverless & Scalable
* 🏢 Enterprise & MSP Ready
