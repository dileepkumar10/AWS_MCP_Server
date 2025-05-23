from dotenv import load_dotenv
import os
import boto3
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta
from typing import List, Dict

# Load environment variables from .env file
load_dotenv()

# Initialize boto3 with credentials from environment variables
session = boto3.Session(
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_REGION', 'us-east-1')  # default to us-east-1 if not specified
)

mcp = FastMCP("AWSCloudManager")

# Clients
sts = session.client("sts")
org = session.client("organizations")
ce = session.client("ce")  # Cost Explorer
ec2 = session.client("ec2")


@mcp.tool()
def detect_account_type() -> str:
    """Determine if the AWS account is Free Tier, Developer, or Enterprise based on spend and org"""
    try:
        spend = get_monthly_spend()
        org_info = org.describe_organization()
        if spend < 20:
            return "Free Tier or Developer Account"
        elif "Organization" in org_info and org_info["Organization"]["FeatureSet"] == "ALL":
            return "Enterprise Account"
        else:
            return "Developer/SMB Account"
    except Exception as e:
        return f"Unable to detect account type: {e}"


def get_monthly_spend() -> float:
    """Get AWS spend for current month using Cost Explorer"""
    start = datetime.today().replace(day=1).strftime('%Y-%m-%d')
    end = datetime.today().strftime('%Y-%m-%d')

    res = ce.get_cost_and_usage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
        Metrics=["UnblendedCost"]
    )
    return float(res["ResultsByTime"][0]["Total"]["UnblendedCost"]["Amount"])


@mcp.tool()
def analyze_billing() -> str:
    """Show AWS spend this month"""
    try:
        spend = get_monthly_spend()
        return f"Current AWS spend this month: ${spend:.2f}"
    except Exception as e:
        return f"Error fetching billing: {e}"


@mcp.tool()
def smart_cost_optimizer() -> List[str]:
    """Give cost-saving tips based on account type and usage"""
    suggestions = []

    try:
        spend = get_monthly_spend()
        acc_type = detect_account_type()
        ec2_instances = ec2.describe_instances()

        # General suggestion
        if spend > 100:
            suggestions.append("Consider setting up AWS Budgets to monitor overspend.")

        # Free tier warnings
        if "Free" in acc_type:
            if spend > 15:
                suggestions.append("You're close to exceeding Free Tier. Review EC2, S3, and Lambda usage.")

        # EC2 Suggestions
        for resv in ec2_instances["Reservations"]:
            for inst in resv["Instances"]:
                state = inst["State"]["Name"]
                inst_type = inst["InstanceType"]
                if state == "stopped":
                    suggestions.append(f"Instance {inst['InstanceId']} is stopped. Consider terminating it.")
                elif inst_type.startswith("t2") and acc_type != "Free Tier":
                    suggestions.append(f"Instance {inst['InstanceId']} is using older generation type ({inst_type}). Consider upgrading to t4g for better price/performance.")

        # Enterprise tips
        if "Enterprise" in acc_type:
            suggestions.append("Consider using Reserved Instances or Savings Plans for long-term workloads.")
            suggestions.append("Enable Cost Anomaly Detection and use Trusted Advisor for deeper optimization.")

        return suggestions or ["No immediate optimizations detected."]
    except Exception as e:
        return [f"Error: {e}"]


@mcp.tool()
def create_ec2_instance(instance_type: str = 't2.micro', ami_id: str = None) -> Dict[str, str]:
    """Create an EC2 instance with specified parameters"""
    try:
        # If no AMI ID is provided, use Amazon Linux 2023 AMI
        if not ami_id:
            # Get the latest Amazon Linux 2023 AMI
            response = ec2.describe_images(
                Filters=[
                    {'Name': 'name', 'Values': ['al2023-ami-2023.*-x86_64']},
                    {'Name': 'state', 'Values': ['available']}
                ],
                Owners=['amazon']
            )
            ami_id = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']

        # Create security group for the instance
        vpc_response = ec2.describe_vpcs()
        vpc_id = vpc_response['Vpcs'][0]['VpcId']  # Using the default VPC

        security_group = ec2.create_security_group(
            GroupName=f'ec2_security_group_{datetime.now().strftime("%Y%m%d_%H%M%S")}',
            Description='Security group for EC2 instance'
        )

        # Allow SSH access (port 22)
        ec2.authorize_security_group_ingress(
            GroupId=security_group['GroupId'],
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )

        # Launch EC2 instance
        instance = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[security_group['GroupId']],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': f'MCPInstance_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                        }
                    ]
                }
            ]
        )

        instance_id = instance['Instances'][0]['InstanceId']

        # Wait for the instance to be running
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])

        # Get instance details
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        instance_details = instance_info['Reservations'][0]['Instances'][0]

        return {
            'InstanceId': instance_id,
            'PublicIpAddress': instance_details.get('PublicIpAddress', 'Not assigned yet'),
            'InstanceType': instance_type,
            'State': instance_details['State']['Name'],
            'SecurityGroupId': security_group['GroupId']
        }

    except Exception as e:
        return {'error': f'Failed to create EC2 instance: {str(e)}'}


@mcp.tool()
def delete_ec2_instance(instance_id: str) -> Dict[str, str]:
    """Delete an EC2 instance by its ID"""
    try:
        # Describe instance to get associated security group
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        if not instance_info['Reservations']:
            return {'error': f'Instance {instance_id} not found'}
        
        instance = instance_info['Reservations'][0]['Instances'][0]
        security_groups = instance.get('SecurityGroups', [])
        
        # Terminate the instance
        ec2.terminate_instances(InstanceIds=[instance_id])
        
        # Wait for the instance to be terminated
        waiter = ec2.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=[instance_id])
        
        # Clean up security groups
        for sg in security_groups:
            try:
                ec2.delete_security_group(GroupId=sg['GroupId'])
            except ec2.exceptions.ResourceInUseException:
                pass  # Skip if security group is still in use
            
        return {
            'status': 'success',
            'message': f'Instance {instance_id} and associated resources have been deleted'
        }
    except Exception as e:
        return {'error': f'Failed to delete EC2 instance: {str(e)}'}


@mcp.tool()
def get_account_creation_date() -> str:
    """Get when the AWS account was created"""
    try:
        # Get account details using IAM
        iam = session.client('iam')
        account_aliases = iam.list_account_aliases()
        account_alias = account_aliases['AccountAliases'][0] if account_aliases['AccountAliases'] else "No alias set"
        
        # Get root user's creation date
        response = iam.get_user(UserName='root')
        creation_date = response['User']['CreateDate']
        
        return f"Account '{account_alias}' was created on {creation_date.strftime('%B %d, %Y')}"
    except Exception as e:
        if "InvalidClientTokenId" in str(e):
            return "Error: Invalid AWS credentials. Please check your AWS access keys."
        elif "AccessDenied" in str(e):
            return "Error: Your IAM user doesn't have permission to check account details."
        else:
            return f"Error checking account creation date: {str(e)}"
