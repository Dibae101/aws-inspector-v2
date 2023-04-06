## Instructions to run the script

### Publish reporting for ECR

    # This will run and publish report for given image with tag.
    python3 ecr_v2.py -i <image_name>:<image_tag>  
    
### Publish Reporting for EC2

    # This will run and publish report for all running ec2 instances.
    python3 ec2_v2.py 