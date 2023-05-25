from slack_sdk import WebClient
from inspector_reporter import InspectorV2Findigs
import os
import pytz
import jinja2
import pdfkit
import boto3

 
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
    
def get_ec2_findings_filter(id):
    """Prepare Inspector v2 filter for EC2 findings filter."""
    ec2_filter = {
        "resourceId": [
            {"comparison": "EQUALS", "value": id},
        ],
        "resourceType": [
            {"comparison": "EQUALS", "value": "AWS_EC2_INSTANCE"},
        ],
    }

    return ec2_filter


def get_ec2_findings(id):
    """Fetch Inspector v2 findings as per provided filter."""
    ec2_instance = ec2.Instance(id)
    tags = ec2_instance.tags
    tag_name = ''
    tag_value = ''
    if tags:
        tags_str = []

        print(tags)
        for tag in tags:
            if tag['Key'] == 'Name':
                tag_name = tag['Value']
            tags_str.append(f"{tag['Key']}: {tag['Value']}")
        tag_value= ', '.join(tags_str)
        print(f"No findings found for EC2 instance {id} with tag name {tag_name} and tag value {tag_value}.")
    
    findings = InspectorV2Findigs(get_ec2_findings_filter(id), tag_name, tag_value).evaluate_findings_for_ec2()
    return findings

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


def report_findings():
    """Report on findings"""
    filters = [
        {
            'Name': 'instance-state-name', 
            'Values': ['running']
        }
    ]
    instances = ec2.instances.filter(Filters=filters)

    for instance in instances:
        print(instance)

    instance_ids = [i.id for i in instances]
    
    for id in instance_ids:
        findings_summary = get_ec2_findings(id)
        # Get the EC2 instance tags if no findings are found
        
        findings_counts = findings_summary['findings_count']
        if not findings_counts:
            print(f"EC2 {id} is clean.")
        else:
            print(
                f"EC2 {id} has the following findings {get_findings_str(findings_counts)}"
            )
        generate_detailed_report(findings_summary)



def generate_detailed_report(findings):
    """Create new HTML report"""
    findings_summary = findings
    scanned_at = findings_summary['scanned_at']
    
    utc_scanned_at = scanned_at.astimezone(pytz.timezone("UTC")).isoformat()
    findings_count = get_findings_str(findings_summary['findings_count'])
    report_file_name = f"{findings_summary['tag_name']}.html"

    report_file = open(report_file_name, mode="w")
    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(loader=template_loader, autoescape=["html"])
    template_file = "report_template_v2.j2"
    template = template_env.get_template(template_file)
    report_file.write(
        template.render(
            ec2_id = findings_summary['ec2_id'],
            tags = findings_summary['tags'],
            scan_date=utc_scanned_at,
            findings_count=findings_count,
            findings=findings_summary['findings'],
            type="AWS_EC2_INSTANCE"
        )
    )
    report_file.close()
    pdf_report_file_name = convert_report_to_pdf(report_file_name)
    send_report_in_slack(pdf_report_file_name)



# main entry function
report_findings()
