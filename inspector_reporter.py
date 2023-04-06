import boto3


class InspectorV2Findigs:
    def __init__(self, filter_criteria, active_status=True) -> None:
        self.client = boto3.client("inspector2")
        if active_status:
            filter_criteria.update(
                {
                    "findingStatus": [
                        {
                            "comparison": "EQUALS",
                            "value": "ACTIVE",
                        },
                    ],
                }
            )

        self.filter_criteria = {"filterCriteria": filter_criteria}

    def get_findigs(self):
        """Fetch findings from inspector v2 with provided filters. Handles pagination internally."""
        
        print(f"Fetching findings from inspector v2 with {self.filter_criteria} filter")

        all_findings = []
        paginator = self.client.get_paginator("list_findings")
        page_iterator = paginator.paginate(**self.filter_criteria)
        for page in page_iterator:
            all_findings.extend(page.get("findings", []))
        return all_findings

    def evaluate_findings_for_ecr(self):
        """Prepare required context for ECR report PDF"""
        
        print("Evaluating findings for ECR.")
        refined_findings = {}
        findings = self.get_findigs()

        if not findings:
            return {}

        refined_findings["findings_count"] = self.evaluate_findings_count(findings)
        refined_findings["findings"] = self.clean_findings_ecr(findings)
        refined_findings["scanned_at"] = findings[0]["updatedAt"]

        return refined_findings

    def evaluate_findings_for_ec2(self):
        """Prepare required context for EC2 report PDF"""
        
        print("Evaluating findings for EC2.")
        refined_findings = {}
        findings = self.get_findigs()
        if not findings:
            return {}

        refined_findings["findings_count"] = self.evaluate_findings_count(findings)
        refined_findings["findings"] = self.clean_findings_ec2(findings)
        refined_findings["scanned_at"] = findings[0]["updatedAt"]
        refined_findings["ec2_id"] = refined_findings["findings"][0]["id"]
        refined_findings["tags"] = refined_findings["findings"][0]["tags"]

        return refined_findings

    def evaluate_findings_count(self, findings):
        print("Preparing severity count.")
        counter = {}
        for finding in findings:
            severity = finding["severity"]
            if severity in counter:
                counter[severity] += 1
            else:
                counter[severity] = 1
        return counter

    def clean_findings_ecr(self, findings):
        """Clean findings data as per ECR findings reponse."""
        
        print("Cleaning data for ECR.")
        cleaned_finds = []
        for finding in findings:
            package_name = ", ".join(
                set(
                    [
                        i.get("name", "")
                        for i in finding.get("packageVulnerabilityDetails", {}).get(
                            "vulnerablePackages", []
                        )
                    ]
                )
            )
            cleaned_finds.append(
                {
                    "name": finding["title"],
                    "uri": finding["packageVulnerabilityDetails"].get("sourceUrl", ""),
                    "severity": finding["severity"],
                    "package": package_name,
                    "description": finding.get("description", ""),
                }
            )
        return cleaned_finds

    def clean_findings_ec2(self, findings):
        """Clean findings data as per EC2 findings reponse."""
        
        print("Cleaning data for EC2.")
        cleaned_finds = []
        for finding in findings:
            ec2_id = finding["resources"][0]["id"]
            tags = finding["resources"][0]["tags"]
            name = finding["resources"][0]["details"]["awsEc2Instance"]["keyName"]
            
            tags_str = []
            for key,val in tags.items():
                tags_str.append(f"{key}: {val}")
                

            cleaned_finds.append(
                {
                    "id": ec2_id,
                    "name": finding["title"],
                    "severity": finding["severity"],
                    "type": finding["type"],
                    "description": finding.get("description", ""),
                    "key_name": name,
                    "tags":', '.join(tags_str)
                }
            )
        return cleaned_finds
