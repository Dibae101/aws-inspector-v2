from slack_sdk import WebClient
from inspector_reporter_ec2 import InspectorV2Findigs
import os
import pytz
import jinja2
import pdfkit
import boto3
import datetime
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--ec_ids", help="EC2 Instance ID")
parser.add_argument("-t", "--tag_name", help="EC2 Tag Name")
ec2 = boto3.resource("ec2")


def convert_report_to_pdf(report_file_name):
    """Convert HTML report to PDF"""
    file_name = report_file_name.split(".")
    file_name_pdf = file_name[0] + ".pdf"
    pdfkit.from_file(report_file_name, file_name_pdf)
    return file_name_pdf


def send_report_in_slack(report_file_name):
    """Sends report_file to ENV VAR SLACK_CHANNEL
    using ENV VAR TOKEN CREDENTIAL"""
    slack_token = os.environ["TOKEN"]
    slack_channel = os.environ["SLACK_CHANNEL"]
    slack_client = WebClient(token=slack_token)
    slack_client.files_upload(
        channels=slack_channel,
        file=report_file_name,
        filename=report_file_name,
        filetype="pdf",
    )


def get_ec2_findings_filter(ids):
    """Prepare Inspector v2 filter for EC2 findings filter."""
    ec2_filter = {
        "resourceId": [],
        "resourceType": [
            {"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"},
        ],
    }
    for id in ids:
        ec2_filter["resourceId"].append({"comparison": "EQUALS", "value": id})

    return ec2_filter


def get_ec2_findings(ids, tag_name):
    """Fetch Inspector v2 findings for multiple EC2 instances."""
    ec2_findings = {}
    for id in ids:
        ec2_instance = ec2.Instance(id)
        tags = ec2_instance.tags
        tag_value = ""
        if tags:
            for tag in tags:
                if tag["Key"] == "Name" and tag["Value"] == tag_name:
                    tag_value = tag["Value"]
                    break

        if tag_value:
            findings = InspectorV2Findigs(
                get_ec2_findings_filter([id]), tag_name, tag_value
            ).evaluate_findings_for_ec2()
            ec2_findings[id] = findings
        else:
            print(
                f"No EC2 instance found with the tag name '{tag_name}' and ID '{id}'."
            )
    return ec2_findings


def get_findings_str(finding_severity_counts):
    """Aggregates findings counts by severity in a string"""
    findings_count_str = ""
    for severity, count in finding_severity_counts.items():
        findings_count_str = findings_count_str + severity + ": " + str(count) + ", "
    if findings_count_str:
        findings_count_str = findings_count_str[:-2] + "."
    else:
        findings_count_str = "0."
    return findings_count_str


def report_findings(tag_name):
    """Report on findings"""
    filters = [
        {
            "Name": "instance-state-name",
            "Values": ["running"],
        }
    ]
    instances = ec2.instances.filter(Filters=filters)
    instance_ids = []
    for instance in instances:
        instance_tags = instance.tags
        if instance_tags:
            for tag in instance_tags:
                if tag["Key"] == "Name" and tag["Value"] == tag_name:
                    instance_ids.append(instance.id)
                    break

    if instance_ids:
        findings_summary = get_ec2_findings(instance_ids, tag_name)
        for id, summary in findings_summary.items():
            findings_counts = summary["findings_count"]
            if not findings_counts:
                print(f"EC2 {id} is clean.")
            else:
                print(
                    f"EC2 {id} has the following findings: {get_findings_str(findings_counts)}"
                )
            generate_detailed_report(summary)
    else:
        print(f"No running EC2 instances found with the tag name '{tag_name}'.")


def generate_detailed_report(findings):
    """Create new HTML report"""
    findings_summary = findings
    scanned_at = findings_summary["scanned_at"]

    utc_scanned_at = scanned_at.astimezone(pytz.timezone("UTC")).isoformat()
    findings_count = get_findings_str(findings_summary["findings_count"])

    report_filename = findings_summary["tag_name"]

    report_file_name = f"{report_filename}.html"

    report_file = open(report_file_name, mode="w")
    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(loader=template_loader, autoescape=["html"])
    template_file = "report_template_v2.j2"
    template = template_env.get_template(template_file)
    report_file.write(
        template.render(
            ec2_id=findings_summary["ec2_id"],
            tags=findings_summary["tags"],
            scan_date=utc_scanned_at,
            findings_count=findings_count,
            findings=findings_summary["findings"],
            type="AWS_EC2_INSTANCE",
        )
    )
    report_file.close()
    pdf_report_file_name = convert_report_to_pdf(report_file_name)
    send_report_in_slack(pdf_report_file_name)


# main entry function
if __name__ == "__main__":
    args = parser.parse_args()
    tag_name = args.tag_name
    if tag_name:
        report_findings(tag_name)
    else:
        print("Please provide a valid EC2 tag name using the -t/--tag_name option.")
