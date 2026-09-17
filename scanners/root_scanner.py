from datetime import datetime, timedelta, timezone

ROOT_ACTIVITY_WINDOW_DAYS = 30

ROOT_HIGH_RISK_EVENTS = {
    "CreateAccessKey",
    "DeleteTrail",
    "StopLogging",
    "PutBucketPolicy",
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole"
}


import boto3
boto3.client("cloudtrail", region_name=region)

def get_cloudtrail_client(region):
    return boto3.client(
        "cloudtrail",
        region_name=region
    )

def lookup_root_events(region):
    cloudtrail = get_cloudtrail_client(region)

    response = cloudtrail.lookup_events(
        LookupAttributes=[
            {
                "AttributeKey": "Username",
                "AttributeValue": "root"
            }
        ],
        MaxResults=50
    )

    return response["Events"]

def audit_root_activity(region):
    event_name = event.get("EventName")

    severity = "HIGH"

    if event_name in ROOT_HIGH_RISK_EVENTS:
        severity = "CRITICAL"

        finding = {
        "service": "ROOT",
        "resource": "AWS Account",
        "check": "ROOT_ACTIVITY",
        "status": "FAIL",
        "severity": severity,
        "event_name": event_name,
        "event_time": str(event.get("EventTime")),
        "event_id": event.get("EventId"),
        "reason": "Root account activity was detected in CloudTrail."
        }
        findings.append(finding)

    return findings

def parse_root_event(event):
    return {
        "event_name": event.get("EventName"),
        "event_time": event.get("EventTime"),
        "username": event.get("Username"),
        "event_id": event.get("EventId"),
        "cloudtrail_event": event.get("CloudTrailEvent")
    }

def is_recent(event_time):
    now = datetime.now(timezone.utc)

    cutoff = now - timedelta(
        days=ROOT_ACTIVITY_WINDOW_DAYS
    )

    return event_time >= cutoff


if __name__ == "__main__":
    findings = audit_root_activity()

    if not findings:
        print("No root account activity detected.")

    for finding in findings:
        print("=" * 60)
        print(f"Service    : {finding['service']}")
        print(f"Resource   : {finding['resource']}")
        print(f"Check      : {finding['check']}")
        print(f"Status     : {finding['status']}")
        print(f"Severity   : {finding['severity']}")
        print(f"Event      : {finding['event_name']}")
        print(f"Event Time : {finding['event_time']}")
        print(f"Reason     : {finding['reason']}")