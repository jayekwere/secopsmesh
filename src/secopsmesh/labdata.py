"""Independently generated synthetic provider-compatible lab records."""

from .domain import stamp

REDACTION_CANARY = "synthetic-redaction-canary"


def fixtures() -> dict[str, dict]:
    t = stamp()
    return {
        "wazuh": {
            "id": "lab-wazuh-001",
            "timestamp": t,
            "agent": {"id": "lab-host-01", "name": "synthetic-linux"},
            "rule": {
                "id": "100501",
                "level": 13,
                "description": "Synthetic suspicious credential access",
                "mitre": {"id": ["T1003"]},
            },
            "data": {"srcuser": "lab-operator", "password": REDACTION_CANARY},
        },
        "aws.guardduty": {
            "id": "lab-gd-001",
            "updatedAt": t,
            "title": "Synthetic anomalous API activity",
            "type": "UnauthorizedAccess:IAMUser/AnomalousBehavior",
            "severity": 8,
            "accountId": "000000000000",
            "region": "us-west-2",
            "resource": {
                "instanceDetails": {"instanceId": "i-synthetic01"},
                "accessKeyDetails": {"userName": "lab-cloud-role"},
            },
        },
        "aws.securityhub": {
            "Id": "lab-sh-001",
            "UpdatedAt": t,
            "Title": "Synthetic exposed security setting",
            "Types": ["Software and Configuration Checks"],
            "Severity": {"Label": "HIGH"},
            "Resources": [{"Id": "arn:aws:ec2:us-west-2:000000000000:instance/i-synthetic01"}],
            "AwsAccountId": "000000000000",
        },
        "aws.cloudtrail": {
            "eventID": "lab-ct-001",
            "eventTime": t,
            "eventName": "StopLogging",
            "recipientAccountId": "000000000000",
            "requestParameters": {"instanceId": "i-synthetic01"},
            "userIdentity": {"arn": "arn:aws:iam::000000000000:role/lab-cloud-role"},
        },
        "azure.defender": {
            "id": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Security/alerts/lab-001",
            "properties": {
                "alertDisplayName": "Synthetic unusual sign-in",
                "alertType": "Identity.UnusualSignIn",
                "severity": "High",
                "timeGeneratedUtc": t,
                "resourceIdentifiers": [
                    {
                        "azureResourceId": "/subscriptions/lab/resourceGroups/synthetic/providers/Microsoft.Compute/virtualMachines/lab-vm"
                    }
                ],
                "compromisedEntity": "lab-azure-user",
            },
        },
        "azure.recommendation": {
            "id": "lab-assessment-001",
            "properties": {
                "displayName": "Synthetic management port exposure",
                "assessmentType": "BuiltIn",
                "metadata": {"severity": "High"},
                "resourceDetails": {"Id": "azure-lab-vm"},
                "timeGeneratedUtc": t,
            },
        },
        "azure.monitor": {
            "id": "lab-monitor-001",
            "time": t,
            "resourceId": "azure-lab-vm",
            "properties": {
                "operationName": "Synthetic privileged operation",
                "severity": "High",
                "timeGeneratedUtc": t,
            },
        },
        "azure.sentinel": {
            "id": "lab-sentinel-001",
            "properties": {
                "title": "Synthetic identity incident",
                "severity": "High",
                "lastModifiedTimeUtc": t,
                "resourceDetails": {"Id": "azure-lab-vm"},
            },
        },
        "azure.sentinel.alert": {
            "id": "lab-sentinel-alert-001",
            "properties": {
                "alertDisplayName": "Synthetic Sentinel incident alert",
                "systemAlertId": "lab-sentinel-alert-001",
                "severity": "High",
                "timeGeneratedUtc": t,
                "resourceDetails": {"Id": "azure-lab-vm"},
            },
        },
        "gcp.scc": {
            "finding": {
                "name": "organizations/000000/sources/000000/findings/lab-scc-001",
                "eventTime": t,
                "category": "SYNTHETIC_PUBLIC_EXPOSURE",
                "severity": "HIGH",
                "resourceName": "//compute.googleapis.com/projects/synthetic-lab/zones/us-west1-a/instances/lab-gcp-vm",
                "sourceProperties": {"principalEmail": "lab-user@synthetic.invalid"},
            }
        },
        "gcp.audit": {
            "insertId": "lab-gcp-audit-001",
            "timestamp": t,
            "protoPayload": {
                "methodName": "SetIamPolicy",
                "resourceName": "//compute.googleapis.com/projects/synthetic-lab/zones/us-west1-a/instances/lab-gcp-vm",
                "authenticationInfo": {"principalEmail": "lab-user@synthetic.invalid"},
            },
        },
        "kubernetes.audit": {
            "auditID": "lab-k8s-001",
            "stageTimestamp": t,
            "verb": "create",
            "objectRef": {
                "resource": "pods",
                "subresource": "exec",
                "namespace": "secopsmesh-lab",
                "name": "lab-workload",
            },
            "user": {"username": "system:serviceaccount:secopsmesh-lab:synthetic"},
        },
        "kubernetes.tetragon": {
            "id": "lab-tetragon-001",
            "time": t,
            "process_exec": {
                "process": {
                    "binary": "/bin/sh",
                    "pod": {
                        "namespace": "secopsmesh-lab",
                        "name": "lab-workload",
                        "workload": "synthetic",
                    },
                }
            },
        },
    }


def lab_aliases() -> dict:
    return {
        "lab": {
            "identity:lab-operator": "lab:hybrid-identity",
            "identity:lab-cloud-role": "lab:hybrid-identity",
            "identity:arn:aws:iam::000000000000:role/lab-cloud-role": "lab:hybrid-identity",
            "asset:i-synthetic01": "lab:hybrid-identity",
            "asset:arn:aws:ec2:us-west-2:000000000000:instance/i-synthetic01": "lab:hybrid-identity",
            "asset:lab-workload": "lab:kubernetes-workload",
        }
    }
