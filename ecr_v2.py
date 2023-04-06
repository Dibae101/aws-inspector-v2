"""This tool schedules AWS ECR Image Scans.
Generates html report and sends it to a Slack channel."""
import os
import datetime
import argparse
from slack_sdk import WebClient
import boto3
import pytz
import jinja2
import pdfkit
from inspector_reporter import InspectorV2Findigs

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "-i",
    "--image",
    metavar="image_repo:image_tag",
    required=True,
    action="append",
    help="""The image to scan. This argument could be passed more than once.
            If you pass latest tag and it does not exist, the tag that
            was most recently pushed on ECR would be scanned instead!""",
)
args = parser.parse_args()
client = boto3.client("ecr")


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


def get_image_details(image_id, tag):
    """ECR desribe_images call by image:tag"""
    return client.describe_images(
        repositoryName=image_id, imageIds=[{"imageTag": tag}]
    )["imageDetails"][0]


def add_image_details():
    """Add image details to global images list"""
    for i, image in enumerate(images):
        images[i]["details"] = get_image_details(image["id"], image["tag"])


def validate_image_args():
    """Checks if argparse image argument has correct format image:tag"""
    for image_arg in args.image:
        imag_tag_args = image_arg.split(":")
        if len(imag_tag_args) != 2:
            print("Wrong format for:" + image_arg)
            parser.print_help()
            exit(1)


def get_images_list():
    """Generate Images list of dicts"""
    images_list = []
    for image_arg in args.image:
        image_id, tag = image_arg.split(":")
        if tag == "latest":
            tag = get_latest_tag(image_id)
        images_list.append(
            {"id": image_id, "tag": tag, "full_image_ref": image_id + ":" + tag}
        )

    return images_list


def get_pushed_ts(image_details):
    """Get ECR pushed timestamp from image_details"""
    return datetime.datetime.timestamp(image_details["imagePushedAt"])


def get_latest_tag(image_id):
    """Checks if latest tag exist on ECR, if it doesn't
    returns the tag that was most recently pushed"""
    try:
        client.describe_images(
            repositoryName=image_id, imageIds=[{"imageTag": "latest"}]
        )
    except client.exceptions.ImageNotFoundException:
        image_pushed_timestamp = 0
        tags_by_timestamp = {}
        tags = client.describe_images(repositoryName=image_id)["imageDetails"]
        for tag in tags:
            if get_pushed_ts(tag) > image_pushed_timestamp:
                image_pushed_timestamp = get_pushed_ts(tag)
            tags_by_timestamp[get_pushed_ts(tag)] = tag["imageTags"][0]
        return tags_by_timestamp[image_pushed_timestamp]
    return "latest"


def populate_image_findings():
    """Fetch and populate ECR scan findings from inspector v2."""
    for image in images:
        image_digest = image["details"]["imageDigest"]

        findings_filter = {
            "ecrImageHash": [
                {"comparison": "EQUALS", "value": image_digest},
            ],
        }
        
        findings = InspectorV2Findigs(
             filter_criteria=findings_filter
        ).evaluate_findings_for_ecr()

        if not findings:
            print(f"No findings found for {image['full_image_ref']}")

        image["findings_summary"] = findings


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
    for image in images:
        findings_summary = image["findings_summary"]
        
        if not findings_summary:
            print(f"No findings found for {image['full_image_ref']}")
            continue
        
        findings_counts = findings_summary['findings_count']
        if not findings_counts:
            print("Image " + image["id"] + ":" + image["tag"] + " is clean.")
        else:
            print(
                "Image "
                + image["id"]
                + ":"
                + image["tag"]
                + " has the following findings -"
                + get_findings_str(findings_counts)
            )
        generate_detailed_report(image)


def generate_detailed_report(image):
    """Create new HTML report"""
    findings_summary = image["findings_summary"]
    scanned_at = findings_summary['scanned_at']
    
    utc_scanned_at = scanned_at.astimezone(pytz.timezone("UTC")).isoformat()
    findings_count = get_findings_str(findings_summary['findings_count'])
    report_file_name = image["id"] + "_" + image["tag"] + ".html"

    report_file = open(report_file_name, mode="w")
    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(loader=template_loader, autoescape=["html"])
    template_file = "report_template_v2.j2"
    template = template_env.get_template(template_file)
    report_file.write(
        template.render(
            image=image["id"],
            tag=image["tag"],
            scan_date=utc_scanned_at,
            findings_count=findings_count,
            findings=findings_summary['findings'],
            type="AWS_ECR_CONTAINER_IMAGE"
        )
    )
    report_file.close()
    pdf_report_file_name = convert_report_to_pdf(report_file_name)
    send_report_in_slack(pdf_report_file_name)


validate_image_args()

images = get_images_list()

add_image_details()

populate_image_findings()

report_findings()
