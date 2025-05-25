from dotenv import load_dotenv
import os
import boto3
from mcp.server.fastmcp import FastMCP
from datetime import datetime, timedelta
from typing import List, Dict, BinaryIO
import json
import base64
import time
import subprocess

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
s3 = session.client('s3')
s3_resource = session.resource('s3')
lambda_client = session.client('lambda')
cloudwatch = session.client('cloudwatch')
logs = session.client('logs')
rds = session.client('rds')
autoscaling = session.client('autoscaling')
kms = session.client('kms')

# AWS Service Clients
ecr = session.client('ecr')
eks = session.client('eks')
ecs = session.client('ecs')
iam = session.client('iam')
kms = session.client('kms')
acm = session.client('acm')
asg = session.client('autoscaling')
appautoscaling = session.client('application-autoscaling')
resourcegroupstaggingapi = session.client('resourcegroupstaggingapi')
codepipeline = session.client('codepipeline')
codebuild = session.client('codebuild')
codedeploy = session.client('codedeploy')
codecommit = session.client('codecommit')


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
        instances = [
            inst for resv in ec2_instances["Reservations"] 
            for inst in resv["Instances"]
        ]
        for inst in instances:
            inst_id = inst["InstanceId"]
            state = inst["State"]["Name"]
            inst_type = inst["InstanceType"]
            
            if state == "stopped":
                suggestions.append(f"Instance {inst_id} is stopped. Consider terminating it.")
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
def import_key_pair(key_name: str, public_key_material: str) -> Dict:
    """Import an SSH key pair to AWS"""
    try:
        response = ec2.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_material.encode()
        )
        return {
            'key_name': response['KeyName'],
            'key_fingerprint': response['KeyFingerprint']
        }
    except Exception as e:
        return {'error': f'Failed to import key pair: {str(e)}'}


@mcp.tool()
def create_ec2_instance(
    instance_type: str = 't2.micro',
    ami_id: str = None,
    vpc_name: str = None,
    vpc_id: str = None,
    subnet_id: str = None,
    key_name: str = None
) -> Dict:
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

        # Create new VPC if not provided
        if not vpc_id and not vpc_name:
            vpc_name = f'vpc-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        
        if vpc_name and not vpc_id:
            vpc_result = create_vpc(vpc_name)
            if 'error' in vpc_result:
                return vpc_result
            vpc_id = vpc_result['vpc_id']
            subnet_id = vpc_result['public_subnet_id']  # Use public subnet by default

        # Create security group for the instance
        sg_result = create_vpc_security_group(
            vpc_id,
            f'ec2-sg-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        )
        if 'error' in sg_result:
            return sg_result
        security_group_id = sg_result['security_group_id']

        # Launch EC2 instance
        launch_params = {
            'ImageId': ami_id,
            'InstanceType': instance_type,
            'MinCount': 1,
            'MaxCount': 1,
            'SecurityGroupIds': [security_group_id],
            'SubnetId': subnet_id,
            'TagSpecifications': [
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
        }

        if key_name:
            launch_params['KeyName'] = key_name

        instance = ec2.run_instances(**launch_params)
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
            'VpcId': vpc_id,
            'SubnetId': subnet_id,
            'SecurityGroupId': security_group_id,
            'KeyName': key_name
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
        creation_date = iam.get_user(UserName='root')['User']['CreateDate']
        
        return f"Account '{account_alias}' was created on {creation_date.strftime('%B %d, %Y')}"
    except Exception as e:
        if "InvalidClientTokenId" in str(e):
            return "Error: Invalid AWS credentials. Please check your AWS access keys."
        elif "AccessDenied" in str(e):
            return "Error: Your IAM user doesn't have permission to check account details."
        else:
            return f"Error checking account creation date: {str(e)}"


# Docker and Container Management
@mcp.tool()
def list_ecr_repositories() -> List[Dict]:
    """List all ECR repositories in the account"""
    try:
        paginator = ecr.get_paginator('describe_repositories')
        repositories = []
        for page in paginator.paginate():
            repositories.extend(page['repositories'])
        return repositories
    except Exception as e:
        return [{'error': f'Failed to list repositories: {str(e)}'}]


@mcp.tool()
def create_ecr_repository(name: str) -> Dict:
    """Create a new ECR repository"""
    try:
        response = ecr.create_repository(
            repositoryName=name,
            imageScanningConfiguration={'scanOnPush': True},
            encryptionConfiguration={'encryptionType': 'AES256'}
        )
        return {
            'repository_uri': response['repository']['repositoryUri'],
            'repository_name': name,
            'registry_id': response['repository']['registryId']
        }
    except Exception as e:
        return {'error': f'Failed to create repository: {str(e)}'}


@mcp.tool()
def delete_ecr_repository(name: str) -> Dict:
    """Delete an ECR repository"""
    try:
        ecr.delete_repository(
            repositoryName=name,
            force=True
        )
        return {
            'status': 'success',
            'message': f'Repository {name} deleted successfully'
        }
    except Exception as e:
        return {'error': f'Failed to delete repository: {str(e)}'}


@mcp.tool()
def get_repository_policy(repository_name: str) -> Dict:
    """Get repository policy and permissions"""
    try:
        response = ecr.get_repository_policy(repositoryName=repository_name)
        return {
            'repository_name': repository_name,
            'policy': json.loads(response['policyText'])
        }
    except ecr.exceptions.RepositoryPolicyNotFoundException:
        return {
            'repository_name': repository_name,
            'policy': 'No policy attached'
        }
    except Exception as e:
        return {'error': f'Failed to get repository policy: {str(e)}'}


@mcp.tool()
def manage_image_tags(
    repository_name: str,
    image_tag: str,
    new_tags: List[str] = None,
    delete_tags: List[str] = None
) -> Dict:
    """Manage image tags - add new tags or delete existing ones"""
    try:
        if new_tags:
            # Get image manifest
            manifest = ecr.batch_get_image(
                repositoryName=repository_name,
                imageIds=[{'imageTag': image_tag}]
            )['images'][0]['imageManifest']
            
            # Add new tags
            ecr.batch_put_image(
                repositoryName=repository_name,
                imageIds=[{'imageTag': tag} for tag in new_tags],
                imageManifest=manifest
            )
        
        if delete_tags:
            ecr.batch_delete_image(
                repositoryName=repository_name,
                imageIds=[{'imageTag': tag} for tag in delete_tags]
            )
        
        return {
            'repository_name': repository_name,
            'original_tag': image_tag,
            'added_tags': new_tags or [],
            'deleted_tags': delete_tags or []
        }
    except Exception as e:
        return {'error': f'Failed to manage image tags: {str(e)}'}


@mcp.tool()
def get_image_scan_findings(repository_name: str, image_tag: str = 'latest') -> Dict:
    """Get security scan findings for a container image"""
    try:
        findings = ecr.describe_image_scan_findings(
            repositoryName=repository_name,
            imageId={'imageTag': image_tag}
        )
        
        return {
            'repository_name': repository_name,
            'image_tag': image_tag,
            'scan_status': findings['imageScanStatus']['status'],
            'findings_count': findings.get('imageScanFindings', {}).get('findingSeverityCounts', {}),
            'vulnerabilities': [
                {
                    'severity': finding['severity'],
                    'name': finding['name'],
                    'package': finding['packageName'],
                    'version': finding['packageVersion']
                }
                for finding in findings.get('imageScanFindings', {}).get('findings', [])
            ]
        }
    except Exception as e:
        return {'error': f'Failed to get scan findings: {str(e)}'}


@mcp.tool()
def set_lifecycle_policy(
    repository_name: str,
    max_images: int = 100,
    untagged_days: int = 14
) -> Dict:
    """Set lifecycle policy for an ECR repository"""
    try:
        policy = {
            'rules': [
                {
                    'rulePriority': 1,
                    'description': 'Remove untagged images',
                    'selection': {
                        'tagStatus': 'untagged',
                        'countType': 'sinceImagePushed',
                        'countUnit': 'days',
                        'countNumber': untagged_days
                    },
                    'action': {'type': 'expire'}
                },
                {
                    'rulePriority': 2,
                    'description': 'Limit maximum images',
                    'selection': {
                        'tagStatus': 'any',
                        'countType': 'imageCountMoreThan',
                        'countNumber': max_images
                    },
                    'action': {'type': 'expire'}
                }
            ]
        }
        
        # Apply the policy
        ecr.put_lifecycle_policy(
            repositoryName=repository_name,
            lifecyclePolicyText=json.dumps(policy)
        )
        
        return {
            'repository_name': repository_name,
            'max_images': max_images,
            'untagged_days': untagged_days,
            'policy': policy
        }
    except Exception as e:
        return {'error': f'Failed to set lifecycle policy: {str(e)}'}


@mcp.tool()
def create_eks_cluster(name: str, nodegroup_name: str = None) -> Dict:
    """Create a new EKS cluster with optional managed node group"""
    try:
        # Create cluster
        cluster_response = eks.create_cluster(
            name=name,
            roleArn=create_eks_role(),
            resourcesVpcConfig={
                'subnetIds': get_default_subnets(),
                'endpointPublicAccess': True,
                'endpointPrivateAccess': True
            }
        )['cluster']
        
        # Wait for cluster to be active
        waiter = eks.get_waiter('cluster_active')
        waiter.wait(name=name)
        
        # Create managed node group if specified
        if nodegroup_name:
            nodegroup_response = eks.create_nodegroup(
                clusterName=name,
                nodegroupName=nodegroup_name,
                subnets=get_default_subnets(),
                instanceTypes=['t3.medium'],
                nodeRole=create_eks_role(),
                scalingConfig={
                    'minSize': 1,
                    'maxSize': 3,
                    'desiredSize': 2
                }
            )
            
            # Wait for nodegroup to be active
            waiter = eks.get_waiter('nodegroup_active')
            waiter.wait(clusterName=name, nodegroupName=nodegroup_name)
        
        # Get latest cluster info
        cluster_info = eks.describe_cluster(name=name)['cluster']
        
        return {
            'cluster_name': name,
            'status': cluster_info['status'],
            'endpoint': cluster_info['endpoint'],
            'nodegroup': nodegroup_name if nodegroup_name else None
        }
    except Exception as e:
        return {'error': f'Failed to create EKS cluster: {str(e)}'}


@mcp.tool()
def delete_eks_cluster(name: str) -> Dict:
    """Delete an EKS cluster and its associated resources"""
    try:
        # Delete all nodegroups first
        nodegroups = eks.list_nodegroups(clusterName=name)['nodegroups']
        for nodegroup in nodegroups:
            eks.delete_nodegroup(clusterName=name, nodegroupName=nodegroup)
            waiter = eks.get_waiter('nodegroup_deleted')
            waiter.wait(clusterName=name, nodegroupName=nodegroup)
        
        # Delete the cluster
        eks.delete_cluster(name=name)
        waiter = eks.get_waiter('cluster_deleted')
        waiter.wait(name=name)
        
        return {
            'status': 'success',
            'message': f'Cluster {name} and associated resources deleted successfully'
        }
    except Exception as e:
        return {'error': f'Failed to delete EKS cluster: {str(e)}'}


# S3 Management
@mcp.tool()
def list_buckets() -> List[Dict]:
    """List all S3 buckets and their basic info"""
    try:
        buckets = s3.list_buckets()['Buckets']
        return [{
            'name': bucket['Name'],
            'created': bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S'),
            'region': s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint'] or 'us-east-1'
        } for bucket in buckets]
    except Exception as e:
        return [{'error': f'Failed to list buckets: {str(e)}'}]


@mcp.tool()
def create_s3_bucket(name: str, region: str = None) -> Dict:
    """Create an S3 bucket with optional region"""
    try:
        if region and region != 'us-east-1':
            bucket = s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        else:
            bucket = s3.create_bucket(Bucket=name)
        
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        return {
            'name': name,
            'location': region or 'us-east-1',
            'versioning': 'enabled'
        }
    except Exception as e:
        return {'error': f'Failed to create bucket: {str(e)}'}


@mcp.tool()
def delete_s3_bucket(name: str, force: bool = False) -> Dict:
    """Delete an S3 bucket. If force=True, delete all contents first"""
    try:
        if force:
            bucket = s3_resource.Bucket(name)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
        
        s3.delete_bucket(Bucket=name)
        return {'status': 'success', 'message': f'Bucket {name} deleted successfully'}
    except Exception as e:
        return {'error': f'Failed to delete bucket: {str(e)}'}


@mcp.tool()
def list_bucket_contents(bucket_name: str, prefix: str = '') -> List[Dict]:
    """List contents of an S3 bucket with optional prefix filter"""
    try:
        paginator = s3.get_paginator('list_objects_v2')
        contents = []
        for page in paginator.paginate(Bucket=bucket_name, Prefix=prefix):
            if 'Contents' in page:
                contents.extend([{
                    'key': obj['Key'],
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S'),
                    'storage_class': obj['StorageClass']
                } for obj in page['Contents']])
        return contents
    except Exception as e:
        return [{'error': f'Failed to list bucket contents: {str(e)}'}]


# Lambda Functions Management
@mcp.tool()
def list_lambda_functions() -> List[Dict]:
    """List all Lambda functions and their configurations"""
    try:
        functions = []
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                metrics = cloudwatch.get_metric_statistics(
                    Namespace='AWS/Lambda',
                    MetricName='Invocations',
                    Dimensions=[{'Name': 'FunctionName', 'Value': func['FunctionName']}],
                    StartTime=datetime.now() - timedelta(hours=24),
                    EndTime=datetime.now(),
                    Period=3600,
                    Statistics=['Sum']
                )['Datapoints']
                
                functions.append({
                    'name': func['FunctionName'],
                    'runtime': func['Runtime'],
                    'memory': func['MemorySize'],
                    'timeout': func['Timeout'],
                    'last_modified': func['LastModified'],
                    'invocations_24h': sum(m['Sum'] for m in metrics) if metrics else 0,
                    'description': func.get('Description', '')
                })
        return functions
    except Exception as e:
        return [{'error': f'Failed to list Lambda functions: {str(e)}'}]


@mcp.tool()
def create_lambda_function(
    name: str,
    runtime: str,
    handler: str,
    code: str,
    memory: int = 128,
    timeout: int = 3,
    environment: Dict = None
) -> Dict:
    """Create a new Lambda function"""
    try:
        # Create ZIP file with function code
        import tempfile
        import zipfile
        
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp:
            with zipfile.ZipFile(tmp.name, 'w') as z:
                z.writestr('lambda_function.py', code)
            
            with open(tmp.name, 'rb') as f:
                zip_bytes = f.read()
        
        # Create the function
        response = lambda_client.create_function(
            FunctionName=name,
            Runtime=runtime,
            Role=create_lambda_role(),  # You'll need to implement this
            Handler=handler,
            Code={'ZipFile': zip_bytes},
            MemorySize=memory,
            Timeout=timeout,
            Environment={'Variables': environment or {}}
        )
        
        return {
            'name': response['FunctionName'],
            'arn': response['FunctionArn'],
            'runtime': response['Runtime'],
            'memory': response['MemorySize'],
            'timeout': response['Timeout']
        }
    except Exception as e:
        return {'error': f'Failed to create Lambda function: {str(e)}'}


@mcp.tool()
def delete_lambda_function(name: str) -> Dict:
    """Delete a Lambda function"""
    try:
        lambda_client.delete_function(FunctionName=name)
        return {'status': 'success', 'message': f'Function {name} deleted successfully'}
    except Exception as e:
        return {'error': f'Failed to delete Lambda function: {str(e)}'}


@mcp.tool()
def get_lambda_logs(function_name: str, hours: int = 24) -> List[Dict]:
    """Get CloudWatch logs for a Lambda function"""
    try:
        log_group_name = f'/aws/lambda/{function_name}'
        log_streams = logs.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=5
        )['logStreams']
        
        all_logs = []
        for stream in log_streams:
            events = logs.get_log_events(
                logGroupName=log_group_name,
                logStreamName=stream['logStreamName'],
                startTime=int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000),
                endTime=int(datetime.now().timestamp() * 1000)
            )['events']
            
            all_logs.extend([{
                'timestamp': datetime.fromtimestamp(e['timestamp']/1000).strftime('%Y-%m-%d %H:%M:%S'),
                'message': e['message']
            } for e in events])
        
        return sorted(all_logs, key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        return [{'error': f'Failed to get Lambda logs: {str(e)}'}]


# CloudWatch Integration
@mcp.tool()
def create_cloudwatch_alarm(
    name: str,
    metric_name: str,
    namespace: str,
    threshold: float,
    comparison_operator: str,
    evaluation_periods: int = 1,
    period: int = 300,
    statistic: str = 'Average'
) -> Dict:
    """Create a CloudWatch alarm for a metric"""
    try:
        cloudwatch.put_metric_alarm(
            AlarmName=name,
            MetricName=metric_name,
            Namespace=namespace,
            Statistic=statistic,
            Period=period,
            EvaluationPeriods=evaluation_periods,
            Threshold=threshold,
            ComparisonOperator=comparison_operator,
            ActionsEnabled=True
        )
        return {
            'name': name,
            'metric': metric_name,
            'namespace': namespace,
            'threshold': threshold,
            'status': 'created'
        }
    except Exception as e:
        return {'error': f'Failed to create alarm: {str(e)}'}

@mcp.tool()
def get_metric_statistics(
    metric_name: str,
    namespace: str,
    hours: int = 24,
    period: int = 300,
    statistics: List[str] = None
) -> Dict:
    """Get CloudWatch metric statistics"""
    try:
        if statistics is None:
            statistics = ['Average', 'Maximum', 'Minimum']
        
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        response = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=start_time,
            EndTime=end_time,
            Period=period,
            Statistics=statistics
        )
        
        return {
            'metric': metric_name,
            'namespace': namespace,
            'datapoints': [{
                'timestamp': dp['Timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                **{stat.lower(): dp[stat] for stat in statistics}
            } for dp in response['Datapoints']]
        }
    except Exception as e:
        return {'error': f'Failed to get metric statistics: {str(e)}'}

@mcp.tool()
def create_dashboard(name: str, widgets: List[Dict]) -> Dict:
    """Create a CloudWatch dashboard"""
    try:
        dashboard_body = {
            'widgets': widgets
        }
        
        cloudwatch.put_dashboard(
            DashboardName=name,
            DashboardBody=json.dumps(dashboard_body)
        )
        
        return {
            'name': name,
            'status': 'created',
            'widget_count': len(widgets)
        }
    except Exception as e:
        return {'error': f'Failed to create dashboard: {str(e)}'}


# RDS Management
@mcp.tool()
def list_db_instances() -> List[Dict]:
    """List all RDS database instances"""
    try:
        instances = rds.describe_db_instances()['DBInstances']
        return [{
            'identifier': db['DBInstanceIdentifier'],
            'engine': db['Engine'],
            'version': db['EngineVersion'],
            'status': db['DBInstanceStatus'],
            'size': db['DBInstanceClass'],
            'storage': db['AllocatedStorage'],
            'endpoint': db.get('Endpoint', {}).get('Address', 'Not available'),
            'multi_az': db['MultiAZ']
        } for db in instances]
    except Exception as e:
        return [{'error': f'Failed to list RDS instances: {str(e)}'}]


@mcp.tool()
def create_db_instance(
    identifier: str,
    engine: str,
    instance_class: str,
    storage: int,
    master_username: str,
    master_password: str,
    multi_az: bool = False,
    engine_version: str = None
) -> Dict:
    """Create a new RDS database instance"""
    try:
        params = {
            'DBInstanceIdentifier': identifier,
            'Engine': engine,
            'DBInstanceClass': instance_class,
            'AllocatedStorage': storage,
            'MasterUsername': master_username,
            'MasterUserPassword': master_password,
            'MultiAZ': multi_az,
            'PubliclyAccessible': True,
            'AutoMinorVersionUpgrade': True,
            'StorageType': 'gp2'
        }
        
        if engine_version:
            params['EngineVersion'] = engine_version
        
        response = rds.create_db_instance(**params)
        db = response['DBInstance']
        
        return {
            'identifier': db['DBInstanceIdentifier'],
            'engine': db['Engine'],
            'status': db['DBInstanceStatus'],
            'size': db['DBInstanceClass'],
            'storage': db['AllocatedStorage']
        }
    except Exception as e:
        return {'error': f'Failed to create RDS instance: {str(e)}'}


@mcp.tool()
def delete_db_instance(identifier: str, skip_snapshot: bool = False) -> Dict:
    """Delete an RDS database instance"""
    try:
        response = rds.delete_db_instance(
            DBInstanceIdentifier=identifier,
            SkipFinalSnapshot=skip_snapshot,
            FinalDBSnapshotIdentifier=f'{identifier}-final-snapshot' if not skip_snapshot else None
        )
        
        return {
            'identifier': identifier,
            'status': response['DBInstance']['DBInstanceStatus'],
            'message': f'Instance {identifier} is being deleted'
        }
    except Exception as e:
        return {'error': f'Failed to delete RDS instance: {str(e)}'}


@mcp.tool()
def start_db_instance(identifier: str) -> Dict:
    """Start an RDS database instance"""
    try:
        response = rds.start_db_instance(DBInstanceIdentifier=identifier)
        return {
            'identifier': identifier,
            'status': response['DBInstance']['DBInstanceStatus'],
            'message': f'Instance {identifier} is starting'
        }
    except Exception as e:
        return {'error': f'Failed to start RDS instance: {str(e)}'}


@mcp.tool()
def stop_db_instance(identifier: str) -> Dict:
    """Stop an RDS database instance"""
    try:
        response = rds.stop_db_instance(DBInstanceIdentifier=identifier)
        return {
            'identifier': identifier,
            'status': response['DBInstance']['DBInstanceStatus'],
            'message': f'Instance {identifier} is stopping'
        }
    except Exception as e:
        return {'error': f'Failed to stop RDS instance: {str(e)}'}


@mcp.tool()
def create_db_snapshot(db_identifier: str, snapshot_id: str = None) -> Dict:
    """Create a snapshot of an RDS database instance"""
    try:
        if not snapshot_id:
            snapshot_id = f'{db_identifier}-snap-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
            
        response = rds.create_db_snapshot(
            DBInstanceIdentifier=db_identifier,
            DBSnapshotIdentifier=snapshot_id
        )
        
        return {
            'instance': db_identifier,
            'snapshot': snapshot_id,
            'status': response['DBSnapshot']['Status'],
            'creation_time': response['DBSnapshot']['SnapshotCreateTime'].strftime('%Y-%m-%d %H:%M:%S')
        }
    except Exception as e:
        return {'error': f'Failed to create snapshot: {str(e)}'}


@mcp.tool()
def get_db_metrics(identifier: str, hours: int = 24) -> Dict:
    """Get performance metrics for an RDS instance"""
    try:
        metrics = {}
        for metric in ['CPUUtilization', 'FreeableMemory', 'ReadIOPS', 'WriteIOPS']:
            response = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName=metric,
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': identifier}],
                StartTime=datetime.now() - timedelta(hours=hours),
                EndTime=datetime.now(),
                Period=300,
                Statistics=['Average']
            )
            
            metrics[metric] = [{
                'timestamp': dp['Timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                'value': dp['Average']
            } for dp in response['Datapoints']]
        
        return {
            'instance': identifier,
            'period_hours': hours,
            'metrics': metrics
        }
    except Exception as e:
        return {'error': f'Failed to get DB metrics: {str(e)}'}


# Security Management
@mcp.tool()
def list_users() -> List[Dict]:
    """List all IAM users and their basic info"""
    try:
        users = iam.list_users()['Users']
        return [{
            'username': user['UserName'],
            'created': user['CreateDate'].strftime('%Y-%m-%d %H:%M:%S'),
            'arn': user['Arn'],
            'last_used': user.get('PasswordLastUsed', 'Never').strftime('%Y-%m-%d %H:%M:%S') if user.get('PasswordLastUsed') else 'Never'
        } for user in users]
    except Exception as e:
        return [{'error': f'Failed to list users: {str(e)}'}]

@mcp.tool()
def create_iam_user(username: str, groups: List[str] = None) -> Dict:
    """Create a new IAM user and optionally add to groups"""
    try:
        created_user = iam.create_user(UserName=username)['User']
        
        if groups:
            for group in groups:
                try:
                    iam.add_user_to_group(
                        GroupName=group,
                        UserName=username
                    )
                except Exception as e:
                    return {'error': f'User created but failed to add to group {group}: {str(e)}'}
        
        # Generate access keys
        access_key = iam.create_access_key(UserName=username)['AccessKey']
        
        return {
            'username': username,
            'arn': created_user['Arn'],
            'access_key_id': access_key['AccessKeyId'],
            'secret_access_key': access_key['SecretAccessKey'],
            'groups': groups or []
        }
    except Exception as e:
        return {'error': f'Failed to create user: {str(e)}'}

@mcp.tool()
def delete_iam_user(username: str) -> Dict:
    """Delete an IAM user and their access keys"""
    try:
        # Delete access keys
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        for key in keys:
            iam.delete_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId']
            )
        
        # Remove from groups
        groups = iam.list_groups_for_user(UserName=username)['Groups']
        for group in groups:
            iam.remove_user_from_group(
                GroupName=group['GroupName'],
                UserName=username
            )
        
        # Delete user
        iam.delete_user(UserName=username)
        
        return {
            'status': 'success',
            'message': f'User {username} and associated resources deleted'
        }
    except Exception as e:
        return {'error': f'Failed to delete user: {str(e)}'}

@mcp.tool()
def manage_security_group(
    name: str,
    description: str,
    vpc_id: str = None,
    ingress_rules: List[Dict] = None,
    egress_rules: List[Dict] = None
) -> Dict:
    """Create or update a security group"""
    try:
        if not vpc_id:
            vpc_id = ec2.describe_vpcs()['Vpcs'][0]['VpcId']
        
        # Create security group
        try:
            sg_id = ec2.create_security_group(
                GroupName=name,
                Description=description,
                VpcId=vpc_id
            )['GroupId']
        except ec2.exceptions.ClientError as e:
            if 'already exists' in str(e):
                groups = ec2.describe_security_groups(
                    Filters=[{'Name': 'group-name', 'Values': [name]}]
                )['SecurityGroups']
                sg_id = groups[0]['GroupId']
            else:
                raise e
        
        # Manage ingress rules
        if ingress_rules:
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=ingress_rules
            )
        
        # Manage egress rules
        if egress_rules:
            ec2.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=egress_rules
            )
        
        return {
            'group_id': sg_id,
            'name': name,
            'vpc_id': vpc_id
        }
    except Exception as e:
        return {'error': f'Failed to manage security group: {str(e)}'}

@mcp.tool()
def create_kms_key(description: str, alias: str = None) -> Dict:
    """Create a new KMS key for encryption"""
    try:
        key = kms.create_key(
            Description=description,
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )['KeyMetadata']
        
        if alias:
            kms.create_alias(
                AliasName=f'alias/{alias}',
                TargetKeyId=key['KeyId']
            )
        
        return {
            'key_id': key['KeyId'],
            'arn': key['Arn'],
            'alias': alias,
            'description': description
        }
    except Exception as e:
        return {'error': f'Failed to create KMS key: {str(e)}'}

@mcp.tool()
def rotate_access_keys(username: str) -> Dict:
    """Rotate IAM user's access keys"""
    try:
        # List existing keys
        existing_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
        
        # Create new key
        new_key = iam.create_access_key(UserName=username)['AccessKey']
        
        # Deactivate old keys
        for key in existing_keys:
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive'
            )
        
        return {
            'username': username,
            'new_access_key_id': new_key['AccessKeyId'],
            'new_secret_access_key': new_key['SecretAccessKey'],
            'deactivated_keys': [k['AccessKeyId'] for k in existing_keys]
        }
    except Exception as e:
        return {'error': f'Failed to rotate access keys: {str(e)}'}

# Auto Scaling Management
@mcp.tool()
def create_auto_scaling_group(
    name: str,
    min_size: int,
    max_size: int,
    desired_capacity: int,
    instance_type: str,
    subnets: List[str] = None,
    launch_template: Dict = None
) -> Dict:
    """Create an Auto Scaling group"""
    try:
        if not subnets:
            subnets = get_default_subnets()
        
        if not launch_template:
            # Create launch template
            template_name = f'{name}-template'
            template_response = ec2.create_launch_template(
                LaunchTemplateName=template_name,
                LaunchTemplateData={
                    'InstanceType': instance_type,
                    'ImageId': get_latest_amazon_linux_ami(),
                    'SecurityGroupIds': [create_basic_security_group()],
                    'UserData': base64.b64encode(b'''#!/bin/bash
                        yum update -y
                        yum install -y aws-cli
                    ''').decode('utf-8')
                }
            )

            # Extract just the fields we need
            launch_template = {
                'LaunchTemplateId': template_response['LaunchTemplate']['LaunchTemplateId'],
                'Version': str(template_response['LaunchTemplate']['LatestVersionNumber'])
            }
            
        asg.create_auto_scaling_group(
            AutoScalingGroupName=name,
            MinSize=min_size,
            MaxSize=max_size,
            DesiredCapacity=desired_capacity,
            VPCZoneIdentifier=','.join(subnets),
            LaunchTemplate=launch_template
        )
        
        return {
            'name': name,
            'min_size': min_size,
            'max_size': max_size,
            'desired_capacity': desired_capacity,
            'subnets': subnets,
            'launch_template': launch_template
        }
    except Exception as e:
        return {'error': f'Failed to create Auto Scaling group: {str(e)}'}

@mcp.tool()
def update_auto_scaling_group(
    name: str,
    min_size: int = None,
    max_size: int = None,
    desired_capacity: int = None
) -> Dict:
    """Update an Auto Scaling group's capacity"""
    try:
        update_params = {'AutoScalingGroupName': name}
        
        if min_size is not None:
            update_params['MinSize'] = min_size
        if max_size is not None:
            update_params['MaxSize'] = max_size
        if desired_capacity is not None:
            update_params['DesiredCapacity'] = desired_capacity
        
        asg.update_auto_scaling_group(**update_params)
        
        # Get updated group info
        group = asg.describe_auto_scaling_groups(
            AutoScalingGroupNames=[name]
        )['AutoScalingGroups'][0]
        
        return {
            'name': name,
            'min_size': group['MinSize'],
            'max_size': group['MaxSize'],
            'desired_capacity': group['DesiredCapacity'],
            'current_size': len(group['Instances'])
        }
    except Exception as e:
        return {'error': f'Failed to update Auto Scaling group: {str(e)}'}

@mcp.tool()
def create_scaling_policy(
    name: str,
    asg_name: str,
    metric_name: str,
    threshold: float,
    adjustment: int,
    cooldown: int = 300
) -> Dict:
    """Create a scaling policy for an Auto Scaling group"""
    try:
        # Create CloudWatch alarm
        alarm_name = f'{name}-alarm'
        cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            MetricName=metric_name,
            Namespace='AWS/EC2',
            Statistic='Average',
            Period=60,
            EvaluationPeriods=2,
            Threshold=threshold,
            ComparisonOperator='GREATER_THAN',
            Dimensions=[{'Name': 'AutoScalingGroupName', 'Value': asg_name}]
        )
        
        # Create scaling policy
        policy = asg.put_scaling_policy(
            AutoScalingGroupName=asg_name,
            PolicyName=name,
            AdjustmentType='ChangeInCapacity',
            ScalingAdjustment=adjustment,
            Cooldown=cooldown
        )
        
        # Link alarm to policy
        cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmActions=[policy['PolicyARN']]
        )
        
        return {
            'policy_name': name,
            'policy_arn': policy['PolicyARN'],
            'alarm_name': alarm_name,
            'metric': metric_name,
            'threshold': threshold,
            'adjustment': adjustment,
            'cooldown': cooldown
        }
    except Exception as e:
        return {'error': f'Failed to create scaling policy: {str(e)}'}

@mcp.tool()
def delete_auto_scaling_group(name: str, force: bool = False) -> Dict:
    """Delete an Auto Scaling group"""
    try:
        asg.delete_auto_scaling_group(
            AutoScalingGroupName=name,
            ForceDelete=force
        )
        return {
            'status': 'success',
            'message': f'Auto Scaling group {name} deleted successfully'
        }
    except Exception as e:
        return {'error': f'Failed to delete Auto Scaling group: {str(e)}'}

# Resource Tagging
@mcp.tool()
def tag_resources(resources: List[str], tags: Dict[str, str]) -> Dict:
    """Tag multiple AWS resources"""
    try:
        formatted_tags = [{'Key': k, 'Value': v} for k, v in tags.items()]
        
        resourcegroupstaggingapi.tag_resources(
            ResourceARNList=resources,
            Tags=formatted_tags
        )
        
        return {
            'status': 'success',
            'tagged_resources': resources,
            'tags': tags
        }
    except Exception as e:
        return {'error': f'Failed to tag resources: {str(e)}'}

@mcp.tool()
def get_resources_by_tag(tag_key: str, tag_value: str = None) -> List[Dict]:
    """Get AWS resources filtered by tags"""
    try:
        filters = [{'Key': tag_key}]
        if tag_value:
            filters[0]['Values'] = [tag_value]
            
        paginator = resourcegroupstaggingapi.get_paginator('get_resources')
        resources = []
        
        for page in paginator.paginate(TagFilters=filters):
            for resource in page['ResourceTagMappingList']:
                resources.append({
                    'arn': resource['ResourceARN'],
                    'tags': {t['Key']: t['Value'] for t in resource['Tags']}
                })
        
        return resources
    except Exception as e:
        return [{'error': f'Failed to get resources by tag: {str(e)}'}]

@mcp.tool()
def get_tag_compliance() -> Dict:
    """Check tag compliance across resources"""
    try:
        required_tags = ['Environment', 'Project', 'Owner']
        resources = resourcegroupstaggingapi.get_resources()['ResourceTagMappingList']
        
        compliant = []
        non_compliant = []
        
        for resource in resources:
            resource_tags = {t['Key']: t['Value'] for t in resource['Tags']}
            missing_tags = [tag for tag in required_tags if tag not in resource_tags]
            
            if missing_tags:
                non_compliant.append({
                    'arn': resource['ResourceARN'],
                    'missing_tags': missing_tags
                })
            else:
                compliant.append(resource['ResourceARN'])
        
        return {
            'compliant_count': len(compliant),
            'non_compliant_count': len(non_compliant),
            'non_compliant_resources': non_compliant
        }
    except Exception as e:
        return {'error': f'Failed to check tag compliance: {str(e)}'}

# Enhanced Cost Management
@mcp.tool()
def get_cost_breakdown() -> Dict:
    """Get detailed cost breakdown by service and tag"""
    try:
        end = datetime.now()
        start = end.replace(day=1)  # Start of current month
        
        # Get costs by service
        service_costs = ce.get_cost_and_usage(
            TimePeriod={'Start': start.strftime('%Y-%m-%d'), 'End': end.strftime('%Y-%m-%d')},
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'DIMENSION', 'Key': 'SERVICE'}]
        )
        
        # Get costs by tag
        tag_costs = ce.get_cost_and_usage(
            TimePeriod={'Start': start.strftime('%Y-%m-%d'), 'End': end.strftime('%Y-%m-%d')},
            Granularity='MONTHLY',
            Metrics=['UnblendedCost'],
            GroupBy=[{'Type': 'TAG', 'Key': 'Environment'}]
        )
        
        return {
            'total_cost': sum(float(group['Metrics']['UnblendedCost']['Amount']) 
                            for group in service_costs['ResultsByTime'][0]['Groups']),
            'by_service': [{
                'service': group['Keys'][0],
                'cost': float(group['Metrics']['UnblendedCost']['Amount'])
            } for group in service_costs['ResultsByTime'][0]['Groups']],
            'by_environment': [{
                'environment': group['Keys'][0].split('$')[-1] or 'untagged',
                'cost': float(group['Metrics']['UnblendedCost']['Amount'])
            } for group in tag_costs['ResultsByTime'][0]['Groups']]
        }
    except Exception as e:
        return {'error': f'Failed to get cost breakdown: {str(e)}'}

@mcp.tool()
def forecast_monthly_costs() -> Dict:
    """Forecast AWS costs for the next month"""
    try:
        end = datetime.now()
        start = end - timedelta(days=30)
        forecast_end = end + timedelta(days=30)
        
        # Get historical costs
        historical = ce.get_cost_forecast(
            TimePeriod={
                'Start': start.strftime('%Y-%m-%d'),
                'End': forecast_end.strftime('%Y-%m-%d')
            },
            Metric='UNBLENDED_COST',
            Granularity='MONTHLY'
        )
        
        return {
            'current_month_forecast': float(historical['Total']['Amount']),
            'next_month_forecast': float(historical['ForecastResultsByTime'][0]['MeanValue']),
            'confidence_interval': {
                'lower': float(historical['ForecastResultsByTime'][0]['PredictionIntervalLowerBound']),
                'upper': float(historical['ForecastResultsByTime'][0]['PredictionIntervalUpperBound'])
            }
        }
    except Exception as e:
        return {'error': f'Failed to forecast costs: {str(e)}'}

@mcp.tool()
def create_budget_alert(
    name: str,
    amount: float,
    email: str,
    threshold: float = 80.0
) -> Dict:
    """Create a budget with email alerts"""
    try:
        budgets = session.client('budgets')
        
        # Create budget and notification
        budgets.create_budget(
            AccountId=sts.get_caller_identity()['Account'],
            Budget={
                'BudgetName': name,
                'BudgetLimit': {
                    'Amount': str(amount),
                    'Unit': 'USD'
                },
                'TimeUnit': 'MONTHLY',
                'BudgetType': 'COST'
            }
        )
        
        # Create notification
        budgets.create_notification(
            AccountId=sts.get_caller_identity()['Account'],
            BudgetName=name,
            Notification={
                'NotificationType': 'ACTUAL',
                'ComparisonOperator': 'GREATER_THAN',
                'Threshold': threshold,
                'ThresholdType': 'PERCENTAGE',
                'NotificationState': 'ALARM'
            },
            Subscribers=[{
                'SubscriptionType': 'EMAIL',
                'Address': email
            }]
        )
        
        return {
            'budget_name': name,
            'amount': amount,
            'threshold': threshold,
            'notification_email': email
        }
    except Exception as e:
        return {'error': f'Failed to create budget alert: {str(e)}'}

# CI/CD Pipeline Management
@mcp.tool()
def create_pipeline(
    name: str,
    repository_name: str,
    branch: str,
    build_spec: str,
    deploy_config: Dict
) -> Dict:
    """Create a complete CI/CD pipeline with CodePipeline, CodeBuild, and CodeDeploy"""
    try:
        # Create CodeBuild project
        build_project = codebuild.create_project(
            name=f'{name}-build',
            source={
                'type': 'CODECOMMIT',
                'location': f'https://git-codecommit.{os.getenv("AWS_REGION")}.amazonaws.com/v1/repos/{repository_name}'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'image': 'aws/codebuild/amazonlinux2-x86_64-standard:4.0'
            },
            serviceRole=create_pipeline_role(),
            artifacts={'type': 'CODEPIPELINE'},
            buildspec=build_spec
        )

        # Create CodeDeploy application and deployment group
        codedeploy.create_application(
            applicationName=f'{name}-app'
        )
        
        deployment_group = codedeploy.create_deployment_group(
            applicationName=f'{name}-app',
            deploymentGroupName=f'{name}-group',
            serviceRoleArn=create_pipeline_role(),
            deploymentStyle={
                'deploymentOption': 'WITH_TRAFFIC_CONTROL',
                'deploymentType': 'IN_PLACE'
            },
            **deploy_config
        )

        # Create CodePipeline
        codepipeline.create_pipeline(
            pipeline={
                'name': name,
                'roleArn': create_pipeline_role(),
                'artifactStore': {
                    'type': 'S3',
                    'location': create_artifact_bucket(name)
                },
                'stages': [
                    {
                        'name': 'Source',
                        'actions': [{
                            'name': 'Source',
                            'actionTypeId': {
                                'category': 'Source',
                                'owner': 'AWS',
                                'provider': 'CodeCommit',
                                'version': '1'
                            },
                            'configuration': {
                                'RepositoryName': repository_name,
                                'BranchName': branch
                            },
                            'outputArtifacts': [{'name': 'SourceCode'}]
                        }]
                    },
                    {
                        'name': 'Build',
                        'actions': [{
                            'name': 'Build',
                            'actionTypeId': {
                                'category': 'Build',
                                'owner': 'AWS',
                                'provider': 'CodeBuild',
                                'version': '1'
                            },
                            'configuration': {
                                'ProjectName': f'{name}-build'
                            },
                            'inputArtifacts': [{'name': 'SourceCode'}],
                            'outputArtifacts': [{'name': 'BuildOutput'}]
                        }]
                    },
                    {
                        'name': 'Deploy',
                        'actions': [{
                            'name': 'Deploy',
                            'actionTypeId': {
                                'category': 'Deploy',
                                'owner': 'AWS',
                                'provider': 'CodeDeploy',
                                'version': '1'
                            },
                            'configuration': {
                                'ApplicationName': f'{name}-app',
                                'DeploymentGroupName': f'{name}-group'
                            },
                            'inputArtifacts': [{'name': 'BuildOutput'}]
                        }]
                    }
                ]
            }
        )

        return {
            'pipeline_name': name,
            'build_project': build_project['project']['name'],
            'deploy_application': f'{name}-app',
            'deploy_group': deployment_group['deploymentGroupId'],
            'status': 'created'
        }
    except Exception as e:
        return {'error': f'Failed to create pipeline: {str(e)}'}

@mcp.tool()
def delete_pipeline(name: str) -> Dict:
    """Delete a complete CI/CD pipeline and associated resources"""
    try:
        # Delete CodePipeline
        codepipeline.delete_pipeline(name=name)
        
        # Delete CodeBuild project
        codebuild.delete_project(name=f'{name}-build')
        
        # Delete CodeDeploy resources
        codedeploy.delete_deployment_group(
            applicationName=f'{name}-app',
            deploymentGroupName=f'{name}-group'
        )
        codedeploy.delete_application(
            applicationName=f'{name}-app'
        )
        
        # Delete artifact bucket
        delete_artifact_bucket(name)
        
        return {
            'status': 'success',
            'message': f'Pipeline {name} and associated resources deleted successfully'
        }
    except Exception as e:
        return {'error': f'Failed to delete pipeline: {str(e)}'}

@mcp.tool()
def get_pipeline_status(name: str) -> Dict:
    """Get the current status of a pipeline and its executions"""
    try:
        # Get pipeline details
        pipeline = codepipeline.get_pipeline(name=name)
        
        # Get recent executions
        executions = codepipeline.list_pipeline_executions(
            pipelineName=name,
            maxResults=5
        )['pipelineExecutionSummaries']
        
        # Get stage states for latest execution
        if executions:
            latest_execution = executions[0]
            states = codepipeline.get_pipeline_state(name=name)['stageStates']
            
            latest_status = {
                'execution_id': latest_execution['pipelineExecutionId'],
                'status': latest_execution['status'],
                'start_time': latest_execution['startTime'].strftime('%Y-%m-%d %H:%M:%S'),
                'stages': [{
                    'name': state['stageName'],
                    'status': state.get('latestExecution', {}).get('status', 'Unknown'),
                    'last_updated': state.get('latestExecution', {}).get('lastUpdateTime', '').strftime('%Y-%m-%d %H:%M:%S') if state.get('latestExecution', {}).get('lastUpdateTime') else None
                } for state in states]
            }
        else:
            latest_status = None
        
        return {
            'pipeline_name': name,
            'version': pipeline['pipeline']['version'],
            'latest_execution': latest_status,
            'recent_executions': [{
                'id': exe['pipelineExecutionId'],
                'status': exe['status'],
                'start_time': exe['startTime'].strftime('%Y-%m-%d %H:%M:%S')
            } for exe in executions]
        }
    except Exception as e:
        return {'error': f'Failed to get pipeline status: {str(e)}'}

@mcp.tool()
def start_pipeline_execution(name: str) -> Dict:
    """Start a new execution of an existing pipeline"""
    try:
        execution = codepipeline.start_pipeline_execution(name=name)
        return {
            'pipeline_name': name,
            'execution_id': execution['pipelineExecutionId'],
            'status': 'started'
        }
    except Exception as e:
        return {'error': f'Failed to start pipeline execution: {str(e)}'}

def create_pipeline_role() -> str:
    """Create IAM role for CI/CD pipeline"""
    try:
        role_name = f'pipeline-role-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        
        # Create role
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Principal': {
                            'Service': [
                                'codepipeline.amazonaws.com',
                                'codebuild.amazonaws.com',
                                'codedeploy.amazonaws.com'
                            ]
                        },
                        'Action': 'sts:AssumeRole'
                    }
                ]
            })
        )
        
        # Attach necessary policies
        policies = [
            'AWSCodePipelineFullAccess',
            'AWSCodeBuildAdminAccess',
            'AWSCodeDeployFullAccess',
            'AmazonS3FullAccess'
        ]
        
        for policy in policies:
            iam.attach_role_policy(
                RoleName=role_name,
                PolicyArn=f'arn:aws:iam::aws:policy/{policy}'
            )
        
        # Wait for role to be available
        time.sleep(10)
        
        return role['Role']['Arn']
    except Exception as e:
        raise Exception(f'Failed to create pipeline role: {str(e)}')

def create_artifact_bucket(pipeline_name: str) -> str:
    """Create S3 bucket for pipeline artifacts"""
    try:
        bucket_name = f'pipeline-artifacts-{pipeline_name}-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={
                'LocationConstraint': os.getenv('AWS_REGION', 'us-east-1')
            } if os.getenv('AWS_REGION') != 'us-east-1' else {}
        )
        
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        return bucket_name
    except Exception as e:
        raise Exception(f'Failed to create artifact bucket: {str(e)}')

def delete_artifact_bucket(pipeline_name: str) -> None:
    """Delete the artifact bucket and its contents"""
    try:
        buckets = s3.list_buckets()['Buckets']
        pipeline_bucket = next(
            (b['Name'] for b in buckets if b['Name'].startswith(f'pipeline-artifacts-{pipeline_name}')),
            None
        )
        
        if pipeline_bucket:
            bucket = s3_resource.Bucket(pipeline_bucket)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            s3.delete_bucket(Bucket=pipeline_bucket)
    except Exception as e:
        raise Exception(f'Failed to delete artifact bucket: {str(e)}')

def get_default_subnets() -> List[str]:
    """Return a list of default subnet IDs from the default VPC"""
    try:
        # Get default VPC
        vpcs = ec2.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )['Vpcs']
        
        if not vpcs:
            raise Exception('No default VPC found')
            
        default_vpc_id = vpcs[0]['VpcId']
        
        # Get subnets in default VPC
        subnets = ec2.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [default_vpc_id]}]
        )['Subnets']
        
        return [subnet['SubnetId'] for subnet in subnets]
    except Exception as e:
        raise Exception(f'Failed to get default subnets: {str(e)}')

def create_eks_role() -> str:
    """
    Create an IAM role for EKS cluster.
    Implement proper role creation logic here.
    For now, returns a dummy role ARN.
    """
    return "arn:aws:iam::123456789012:role/YourEKSRole"

def create_lambda_role() -> str:
    """
    Create an IAM role for Lambda functions.
    Implement proper role creation logic here.
    For now, returns a dummy role ARN.
    """
    return "arn:aws:iam::123456789012:role/YourLambdaRole"

def get_latest_amazon_linux_ami() -> str:
    """
    Retrieve the latest Amazon Linux 2 AMI ID.
    """
    response = ec2.describe_images(
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']}
        ],
        Owners=['amazon']
    )
    latest_ami = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
    return latest_ami

def create_basic_security_group() -> str:
    """Create a basic security group and return its ID."""
    vpc_response = ec2.describe_vpcs()
    vpc_id = vpc_response['Vpcs'][0]['VpcId']
    sg = ec2.create_security_group(
        GroupName=f'basic-sg-{datetime.now().strftime("%Y%m%d%H%M%S")}',
        Description='Basic security group',
        VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[
            {
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }
        ]
    )
    return sg['GroupId']


# Python Project Deployment
@mcp.tool()
def setup_python_deployment(
    project_name: str,
    deployment_type: str = 'lambda',  # or 'ec2'
    python_version: str = '3.9',
    requirements_file: str = 'requirements.txt'
) -> Dict:
    """Set up deployment pipeline for a Python project"""
    try:
        # Create CodeCommit repository
        try:
            repo = codecommit.create_repository(
                repositoryName=project_name,
                repositoryDescription=f'Python project repository for {project_name}'
            )
        except codecommit.exceptions.RepositoryNameExistsException:
            repo = codecommit.get_repository(repositoryName=project_name)
        
        # Create buildspec.yml content based on deployment type
        buildspec = {
            'version': '0.2',
            'phases': {
                'install': {
                    'runtime-versions': {
                        'python': python_version
                    },
                    'commands': [
                        'pip install --upgrade pip',
                        f'pip install -r {requirements_file}'
                    ]
                },
                'pre_build': {
                    'commands': [
                        'pytest tests/'
                    ]
                },
                'build': {
                    'commands': [
                        'python setup.py bdist_wheel'
                    ]
                }
            },
            'artifacts': {
                'files': [
                    '**/*'
                ]
            }
        }

        if deployment_type == 'lambda':
            buildspec['phases']['build']['commands'].extend([
                'mkdir -p build/lambda',
                'cp -r * build/lambda/',
                'cd build/lambda && zip -r ../../deployment.zip .'
            ])
        else:  # EC2
            buildspec['phases']['build']['commands'].extend([
                'mkdir -p build/ec2',
                'cp -r * build/ec2/',
                'tar -czf deployment.tar.gz build/ec2/'
            ])

        # Create the pipeline
        create_pipeline(
            name=f'{project_name}-pipeline',
            repository_name=project_name,
            branch='main',
            build_spec=json.dumps(buildspec),
            deploy_config={
                'ec2TagSet': {
                    'ec2TagSetList': [[
                        {'Key': 'Project', 'Value': project_name},
                        {'Key': 'Environment', 'Value': 'Production'}
                    ]]
                }
            } if deployment_type == 'ec2' else {
                'deploymentStyle': {
                    'deploymentType': 'ALL_AT_ONCE',
                    'deploymentOption': 'WITH_TRAFFIC_CONTROL'
                }
            }
        )

        # Create deployment environment based on type
        if deployment_type == 'lambda':
            function_response = create_lambda_function(
                name=f'{project_name}-function',
                runtime=f'python{python_version}',
                handler='main.handler',
                code='def handler(event, context):\n    return {"statusCode": 200, "body": "Hello from Lambda!"}',
                memory=256,
                timeout=30
            )
            deployment_target = function_response.get('arn', 'Failed to create Lambda function')
        else:
            instance_response = create_ec2_instance(
                instance_type='t2.micro',
                ami_id=get_python_ami(python_version)
            )
            deployment_target = instance_response.get('InstanceId', 'Failed to create EC2 instance')

        return {
            'status': 'success',
            'repository_url': repo['repositoryMetadata']['cloneUrlHttp'],
            'pipeline_name': f'{project_name}-pipeline',
            'deployment_type': deployment_type,
            'deployment_target': deployment_target,
            'next_steps': [
                'git clone ' + repo['repositoryMetadata']['cloneUrlHttp'],
                'cd ' + project_name,
                'git add .',
                'git commit -m "Initial commit"',
                'git push'
            ]
        }
    except Exception as e:
        return {'error': f'Failed to set up deployment: {str(e)}'}

@mcp.tool()
def deploy_python_project(
    project_path: str,
    environment_variables: Dict = None
) -> Dict:
    """Deploy a Python project to AWS"""
    try:
        # Get project name from directory
        project_name = os.path.basename(project_path)
        
        # Check for required files
        required_files = ['setup.py', 'requirements.txt', 'tests']
        missing_files = [f for f in required_files if not os.path.exists(os.path.join(project_path, f))]
        if missing_files:
            return {'error': f'Missing required files/directories: {", ".join(missing_files)}'}
        
        # Set up deployment pipeline
        setup_response = setup_python_deployment(
            project_name=project_name,
            deployment_type='lambda' if has_lambda_handler(project_path) else 'ec2',
            python_version=get_project_python_version(project_path),
            requirements_file='requirements.txt'
        )
        
        if 'error' in setup_response:
            return setup_response
        
        # Add environment variables if provided
        if environment_variables:
            if 'function' in setup_response['deployment_target']:
                lambda_client.update_function_configuration(
                    FunctionName=setup_response['deployment_target'],
                    Environment={'Variables': environment_variables}
                )
            else:
                # For EC2, add environment variables to user data script
                instance_id = setup_response['deployment_target']
                update_instance_environment(instance_id, environment_variables)
        
        return {
            'status': 'success',
            'message': 'Deployment pipeline created successfully',
            'repository_url': setup_response['repository_url'],
            'pipeline_name': setup_response['pipeline_name'],
            'deployment_type': setup_response['deployment_type'],
            'next_steps': setup_response['next_steps']
        }
    except Exception as e:
        return {'error': f'Failed to deploy project: {str(e)}'}

def has_lambda_handler(project_path: str) -> bool:
    """Check if project has a Lambda handler function"""
    try:
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    with open(os.path.join(root, file)) as f:
                        if 'def handler(event, context):' in f.read():
                            return True
        return False
    except Exception:
        return False

def get_project_python_version(project_path: str) -> str:
    """Get Python version from project settings"""
    try:
        # Try pyproject.toml first
        if os.path.exists(os.path.join(project_path, 'pyproject.toml')):
            with open(os.path.join(project_path, 'pyproject.toml')) as f:
                content = f.read()
                if 'requires-python' in content:
                    version = content.split('requires-python')[1].split('=')[1].strip().strip('"').strip("'")
                    return version.replace('>=', '').split('.')[0] + '.' + version.split('.')[1]
        
        # Try setup.py
        if os.path.exists(os.path.join(project_path, 'setup.py')):
            with open(os.path.join(project_path, 'setup.py')) as f:
                content = f.read()
                if 'python_requires' in content:
                    version = content.split('python_requires')[1].split('=')[1].strip().strip('"').strip("'")
                    return version.replace('>=', '').split('.')[0] + '.' + version.split('.')[1]
        
        return '3.9'  # Default to Python 3.9 if not specified
    except Exception:
        return '3.9'

def get_python_ami(python_version: str) -> str:
    """Get latest Amazon Linux 2 AMI and configure it for Python"""
    try:
        # Get base Amazon Linux 2 AMI
        response = ec2.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ],
            Owners=['amazon']
        )
        
        ami_id = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
        
        return ami_id
    except Exception as e:
        raise Exception(f'Failed to get Python AMI: {str(e)}')

def update_instance_environment(instance_id: str, environment_variables: Dict) -> None:
    """Update EC2 instance environment variables"""
    try:
        # Create environment file content
        env_content = '\n'.join([f'export {k}="{v}"' for k, v in environment_variables.items()])
        
        # Create user data script
        user_data = f"""#!/bin/bash
echo '{env_content}' > /etc/environment
source /etc/environment
"""
        
        # Update instance user data
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            UserData={'Value': base64.b64encode(user_data.encode()).decode()}
        )
    except Exception as e:
        raise Exception(f'Failed to update instance environment: {str(e)}')


# Docker Management
@mcp.tool()
def create_docker_deployment(
    project_name: str,
    docker_file_path: str = None,
    target_platform: str = 'ecs',  # or 'eks'
    container_port: int = 80,
    environment: Dict[str, str] = None
) -> Dict:
    """Create Docker deployment infrastructure for a project"""
    try:
        # Create ECR repository
        repo_response = create_ecr_repository(project_name)
        if 'error' in repo_response:
            return repo_response

        # Set up ECS or EKS based on target platform
        if target_platform == 'ecs':
            # Create ECS cluster
            cluster_name = f'{project_name}-cluster'
            ecs.create_cluster(
                clusterName=cluster_name,
                capacityProviders=['FARGATE'],
                defaultCapacityProviderStrategy=[{
                    'capacityProvider': 'FARGATE',
                    'weight': 1
                }]
            )

            # Create task definition
            task_def = ecs.register_task_definition(
                family=f'{project_name}-task',
                networkMode='awsvpc',
                requiresCompatibilities=['FARGATE'],
                cpu='256',
                memory='512',
                executionRoleArn=create_ecs_execution_role(),
                containerDefinitions=[{
                    'name': project_name,
                    'image': f'{repo_response["uri"]}:latest',
                    'portMappings': [{
                        'containerPort': container_port,
                        'protocol': 'tcp'
                    }],
                    'environment': [{'name': k, 'value': v} for k, v in (environment or {}).items()]
                }]
            )

            # Create service
            service = ecs.create_service(
                cluster=cluster_name,
                serviceName=f'{project_name}-service',
                taskDefinition=task_def['taskDefinition']['taskDefinitionArn'],
                desiredCount=1,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': get_default_subnets(),
                        'assignPublicIp': 'ENABLED'
                    }
                }
            )

            deployment_info = {
                'type': 'ecs',
                'cluster': cluster_name,
                'service': service['service']['serviceName'],
                'task_definition': task_def['taskDefinition']['taskDefinitionArn']
            }

        else:  # eks
            # Create EKS cluster if not exists
            cluster_name = f'{project_name}-cluster'
            eks_cluster = create_eks_cluster(
                name=cluster_name,
                nodegroup_name=f'{project_name}-nodes'
            )

            # Create Kubernetes deployment manifest
            deployment_manifest = {
                'apiVersion': 'apps/v1',
                'kind': 'Deployment',
                'metadata': {'name': project_name},
                'spec': {
                    'replicas': 1,
                    'selector': {'matchLabels': {'app': project_name}},
                    'template': {
                        'metadata': {'labels': {'app': project_name}},
                        'spec': {
                            'containers': [{
                                'name': project_name,
                                'image': f'{repo_response["uri"]}:latest',
                                'ports': [{'containerPort': container_port}],
                                'env': [{'name': k, 'value': v} for k, v in (environment or {}).items()]
                            }]
                        }
                    }
                }
            }

            deployment_info = {
                'type': 'eks',
                'cluster': cluster_name,
                'manifest': deployment_manifest
            }

        # Create build pipeline for Docker
        buildspec = {
            'version': '0.2',
            'phases': {
                'pre_build': {
                    'commands': [
                        'aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ECR_REPO_URI',
                        'COMMIT_HASH=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c 1-7)',
                        'IMAGE_TAG=${COMMIT_HASH:=latest}'
                    ]
                },
                'build': {
                    'commands': [
                        'docker build -t $ECR_REPO_URI:$IMAGE_TAG .',
                        'docker tag $ECR_REPO_URI:$IMAGE_TAG $ECR_REPO_URI:latest'
                    ]
                },
                'post_build': {
                    'commands': [
                        'docker push $ECR_REPO_URI:$IMAGE_TAG',
                        'docker push $ECR_REPO_URI:latest',
                        'echo Writing image definitions file...',
                        'printf \'{"ImageURI":"%s"}\' $ECR_REPO_URI:$IMAGE_TAG > imageDefinitions.json'
                    ]
                }
            },
            'artifacts': {
                'files': ['imageDefinitions.json']
            }
        }

        # Create pipeline
        pipeline = create_pipeline(
            name=f'{project_name}-docker-pipeline',
            repository_name=project_name,
            branch='main',
            build_spec=json.dumps(buildspec),
            deploy_config={'containerPort': container_port}
        )

        return {
            'status': 'success',
            'repository': repo_response['uri'],
            'deployment': deployment_info,
            'pipeline': pipeline['pipeline_name'],
            'next_steps': [
                'Add Dockerfile to your project',
                'git add . && git commit -m "Add Docker configuration"',
                'git push origin main'
            ]
        }
    except Exception as e:
        return {'error': f'Failed to create Docker deployment: {str(e)}'}

@mcp.tool()
def build_and_push_docker_image(
    image_name: str,
    dockerfile_path: str,
    repository_uri: str,
    build_args: Dict[str, str] = None
) -> Dict:
    """Build and push a Docker image to ECR"""
    try:
        # Get ECR login token
        token = ecr.get_authorization_token()
        username, password = base64.b64decode(token['authorizationData'][0]['authorizationToken']).decode().split(':')
        registry = token['authorizationData'][0]['proxyEndpoint']

        # Prepare docker build command
        build_cmd = ['docker', 'build', '-t', image_name]
        if build_args:
            for key, value in build_args.items():
                build_cmd.extend(['--build-arg', f'{key}={value}'])
        build_cmd.extend(['-f', dockerfile_path, '.'])

        # Build image
        subprocess.run(build_cmd, check=True)

        # Tag image
        subprocess.run(['docker', 'tag', image_name, f'{repository_uri}:latest'], check=True)

        # Login to ECR
        subprocess.run(['docker', 'login', '--username', username, '--password', password, registry], check=True)

        # Push image
        subprocess.run(['docker', 'push', f'{repository_uri}:latest'], check=True)

        return {
            'status': 'success',
            'image': f'{repository_uri}:latest',
            'message': 'Image built and pushed successfully'
        }
    except subprocess.CalledProcessError as e:
        return {'error': f'Docker command failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Failed to build and push image: {str(e)}'}

@mcp.tool()
def deploy_docker_compose(
    compose_file: str,
    project_name: str,
    platform: str = 'ecs'  # or 'local'
) -> Dict:
    """Deploy a Docker Compose application to ECS or locally"""
    try:
        if not os.path.exists(compose_file):
            return {'error': f'Compose file not found: {compose_file}'}

        if platform == 'ecs':
            # Convert docker-compose to ECS
            subprocess.run(['docker', 'compose', 'convert', '--format', 'ecs', '--output', f'{project_name}-ecs.json'],
                         check=True)

            # Create ECS resources
            with open(f'{project_name}-ecs.json') as f:
                ecs_config = json.load(f)

            # Create ECS cluster
            ecs.create_cluster(clusterName=project_name)

            # Register task definition
            task_def = ecs.register_task_definition(**ecs_config['TaskDefinition'])

            # Create service
            service = ecs.create_service(
                cluster=project_name,
                serviceName=f'{project_name}-service',
                taskDefinition=task_def['taskDefinition']['taskDefinitionArn'],
                desiredCount=1,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': get_default_subnets(),
                        'assignPublicIp': 'ENABLED'
                    }
                }
            )

            return {
                'status': 'success',
                'platform': 'ecs',
                'cluster': project_name,
                'service': service['service']['serviceName'],
                'task_definition': task_def['taskDefinition']['taskDefinitionArn']
            }
        else:  # local
            # Run docker-compose locally
            subprocess.run(['docker-compose', '-f', compose_file, '-p', project_name, 'up', '-d'], check=True)

            return {
                'status': 'success',
                'platform': 'local',
                'project': project_name,
                'message': 'Docker Compose application started locally'
            }
    except subprocess.CalledProcessError as e:
        return {'error': f'Docker command failed: {str(e)}'}
    except Exception as e:
        return {'error': f'Failed to deploy Docker Compose: {str(e)}'}

def create_ecs_execution_role() -> str:
    """Create IAM role for ECS task execution"""
    try:
        role_name = f'ecs-execution-role-{datetime.now().strftime("%Y%m%d-%H%M%S")}'
        
        # Create role
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                'Version': '2012-10-17',
                'Statement': [{
                    'Effect': 'Allow',
                    'Principal': {'Service': 'ecs-tasks.amazonaws.com'},
                    'Action': 'sts:AssumeRole'
                }]
            })
        )
        
        # Attach necessary policies
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'
        )
        
        # Wait for role to be available
        time.sleep(10)
        
        return role['Role']['Arn']
    except Exception as e:
        raise Exception(f'Failed to create ECS execution role: {str(e)}')
@mcp.tool()
def create_ecs_cluster(cluster_name: str) -> Dict:
    """Create a new ECS cluster"""
    try:
        response = ecs.create_cluster(
            clusterName=cluster_name,
            capacityProviders=['FARGATE', 'FARGATE_SPOT'],
            defaultCapacityProviderStrategy=[
                {
                    'capacityProvider': 'FARGATE',
                    'weight': 1,
                    'base': 1
                }
            ]
        )
        return {
            'cluster_name': cluster_name,
            'cluster_arn': response['cluster']['clusterArn'],
            'status': response['cluster']['status']
        }
    except Exception as e:
        return {'error': f'Failed to create ECS cluster: {str(e)}'}

@mcp.tool()
def delete_ecs_cluster(cluster_name: str) -> Dict:
    """Delete an ECS cluster"""
    try:
        ecs.delete_cluster(cluster=cluster_name)
        return {
            'status': 'success',
            'message': f'Cluster {cluster_name} deleted successfully'
        }
    except Exception as e:
        return {'error': f'Failed to delete ECS cluster: {str(e)}'}

@mcp.tool()
def deploy_to_ecs(
    cluster_name: str,
    service_name: str,
    image_uri: str,
    container_port: int = 80,
    desired_count: int = 1,
    cpu: str = '256',
    memory: str = '512'
) -> Dict:
    """Deploy a container to ECS Fargate"""
    try:
        # Create task definition
        task_def = ecs.register_task_definition(
            family=service_name,
            requiresCompatibilities=['FARGATE'],
            networkMode='awsvpc',
            cpu=cpu,
            memory=memory,
            executionRoleArn=create_ecs_execution_role(),
            containerDefinitions=[{
                'name': service_name,
                'image': image_uri,
                'portMappings': [{
                    'containerPort': container_port,
                    'protocol': 'tcp'
                }],
                'essential': True,
                'logConfiguration': {
                    'logDriver': 'awslogs',
                    'options': {
                        'awslogs-group': f'/ecs/{service_name}',
                        'awslogs-region': session.region_name,
                        'awslogs-stream-prefix': 'ecs'
                    }
                }
            }]
        )

        # Create or update service
        try:
            service = ecs.describe_services(
                cluster=cluster_name,
                services=[service_name]
            )['services'][0]
            
            # Update existing service
            service = ecs.update_service(
                cluster=cluster_name,
                service=service_name,
                taskDefinition=task_def['taskDefinition']['taskDefinitionArn'],
                desiredCount=desired_count
            )
        except (IndexError, ecs.exceptions.ServiceNotFoundException):
            # Create new service
            service = ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition=task_def['taskDefinition']['taskDefinitionArn'],
                desiredCount=desired_count,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': get_default_subnets(),
                        'assignPublicIp': 'ENABLED'
                    }
                }
            )

        return {
            'cluster_name': cluster_name,
            'service_name': service_name,
            'task_definition': task_def['taskDefinition']['taskDefinitionArn'],
            'service_arn': service['serviceArn'],
            'status': service['status']
        }
    except Exception as e:
        return {'error': f'Failed to deploy to ECS: {str(e)}'}

@mcp.tool()
def stop_ecs_service(cluster_name: str, service_name: str) -> Dict:
    """Stop an ECS service by setting desired count to 0"""
    try:
        response = ecs.update_service(
            cluster=cluster_name,
            service=service_name,
            desiredCount=0
        )
        return {
            'cluster_name': cluster_name,
            'service_name': service_name,
            'status': response['service']['status'],
            'desired_count': response['service']['desiredCount']
        }
    except Exception as e:
        return {'error': f'Failed to stop ECS service: {str(e)}'}

@mcp.tool()
def get_ecs_metrics(cluster_name: str) -> Dict:
    """Get key metrics for an ECS cluster"""
    try:
        response = cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    'Id': 'cpu',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/ECS',
                            'MetricName': 'CPUUtilization',
                            'Dimensions': [
                                {'Name': 'ClusterName', 'Value': cluster_name}
                            ]
                        },
                        'Period': 300,
                        'Stat': 'Average'
                    }
                },
                {
                    'Id': 'memory',
                    'MetricStat': {
                        'Metric': {
                            'Namespace': 'AWS/ECS',
                            'MetricName': 'MemoryUtilization',
                            'Dimensions': [
                                {'Name': 'ClusterName', 'Value': cluster_name}
                            ]
                        },
                        'Period': 300,
                        'Stat': 'Average'
                    }
                }
            ],
            StartTime=datetime.now() - timedelta(hours=1),
            EndTime=datetime.now()
        )

        return {
            'cluster_name': cluster_name,
            'metrics': {
                'cpu_utilization': response['MetricDataResults'][0],
                'memory_utilization': response['MetricDataResults'][1]
            }
        }
    except Exception as e:
        return {'error': f'Failed to get ECS metrics: {str(e)}'}

@mcp.tool()
def create_service_autoscaling(
    cluster_name: str,
    service_name: str,
    min_tasks: int = 1,
    max_tasks: int = 10,
    target_cpu_util: int = 75,
    target_memory_util: int = 75
) -> Dict:
    """Configure auto scaling for an ECS service"""
    try:
        # Validate service exists
        ecs.describe_services(
            cluster=cluster_name,
            services=[service_name]
        )['services'][0]

        # Register scalable target
        appautoscaling.register_scalable_target(
            ServiceNamespace='ecs',
            ResourceId=f'service/{cluster_name}/{service_name}',
            ScalableDimension='ecs:service:DesiredCount',
            MinCapacity=min_tasks,
            MaxCapacity=max_tasks
        )

        # Create CPU utilization policy
        appautoscaling.put_scaling_policy(
            ServiceNamespace='ecs',
            ResourceId=f'service/{cluster_name}/{service_name}',
            ScalableDimension='ecs:service:DesiredCount',
            PolicyName=f'{service_name}-cpu-target-tracking',
            PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': target_cpu_util,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'ECSServiceAverageCPUUtilization'
                },
                'ScaleOutCooldown': 300,
                'ScaleInCooldown': 300
            }
        )

        # Create memory utilization policy
        appautoscaling.put_scaling_policy(
            ServiceNamespace='ecs',
            ResourceId=f'service/{cluster_name}/{service_name}',
            ScalableDimension='ecs:service:DesiredCount',
            PolicyName=f'{service_name}-memory-target-tracking',
            PolicyType='TargetTrackingScaling',
            TargetTrackingScalingPolicyConfiguration={
                'TargetValue': target_memory_util,
                'PredefinedMetricSpecification': {
                    'PredefinedMetricType': 'ECSServiceAverageMemoryUtilization'
                },
                'ScaleOutCooldown': 300,
                'ScaleInCooldown': 300
            }
        )

        return {
            'cluster_name': cluster_name,
            'service_name': service_name,
            'min_tasks': min_tasks,
            'max_tasks': max_tasks,
            'target_cpu_util': target_cpu_util,
            'target_memory_util': target_memory_util,
            'status': 'Auto scaling configured successfully'
        }
    except Exception as e:
        return {'error': f'Failed to configure auto scaling: {str(e)}'}

@mcp.tool()
def create_vpc(name: str, cidr_block: str = '10.0.0.0/16') -> Dict:
    """Create a VPC with public and private subnets"""
    try:
        # Create VPC
        vpc = ec2.create_vpc(CidrBlock=cidr_block)
        vpc_id = vpc['Vpc']['VpcId']

        # Add name tag to VPC
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=[{'Key': 'Name', 'Value': name}]
        )

        # Enable DNS hostname support
        ec2.modify_vpc_attribute(
            VpcId=vpc_id,
            EnableDnsHostnames={'Value': True}
        )

        # Create an Internet Gateway
        igw = ec2.create_internet_gateway()
        igw_id = igw['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(
            InternetGatewayId=igw_id,
            VpcId=vpc_id
        )

        # Create public subnet (in first AZ)
        az = ec2.describe_availability_zones()['AvailabilityZones'][0]['ZoneName']
        public_subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.1.0/24',
            AvailabilityZone=az
        )
        public_subnet_id = public_subnet['Subnet']['SubnetId']

        # Create private subnet (in first AZ)
        private_subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.2.0/24',
            AvailabilityZone=az
        )
        private_subnet_id = private_subnet['Subnet']['SubnetId']

        # Create and configure route table for public subnet
        public_route_table = ec2.create_route_table(VpcId=vpc_id)
        public_rt_id = public_route_table['RouteTable']['RouteTableId']
        
        # Add route to Internet Gateway
        ec2.create_route(
            RouteTableId=public_rt_id,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id
        )
        
        # Associate public subnet with public route table
        ec2.associate_route_table(
            RouteTableId=public_rt_id,
            SubnetId=public_subnet_id
        )

        # Enable auto-assign public IP for public subnet
        ec2.modify_subnet_attribute(
            SubnetId=public_subnet_id,
            MapPublicIpOnLaunch={'Value': True}
        )

        return {
            'vpc_id': vpc_id,
            'public_subnet_id': public_subnet_id,
            'private_subnet_id': private_subnet_id,
            'internet_gateway_id': igw_id
        }
    except Exception as e:
        return {'error': f'Failed to create VPC: {str(e)}'}

@mcp.tool()
def create_vpc_security_group(vpc_id: str, name: str) -> Dict:
    """Create a security group for the VPC with basic rules"""
    try:
        # Create security group
        security_group = ec2.create_security_group(
            GroupName=name,
            Description=f'Security group for {name}',
            VpcId=vpc_id
        )
        
        sg_id = security_group['GroupId']

        # Add inbound rules
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH access'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP access'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS access'}]
                }
            ]
        )

        return {
            'security_group_id': sg_id,
            'vpc_id': vpc_id
        }
    except Exception as e:
        return {'error': f'Failed to create security group: {str(e)}'}

@mcp.tool()
def list_ec2_instances() -> List[Dict]:
    """List all EC2 instances and their details"""
    try:
        instances = []
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_info = {
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launch_time': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                        'public_ip': instance.get('PublicIpAddress', 'Not assigned'),
                        'private_ip': instance.get('PrivateIpAddress', 'Not assigned'),
                        'vpc_id': instance.get('VpcId', 'Not in VPC'),
                        'subnet_id': instance.get('SubnetId', 'No subnet'),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    }
                    instances.append(instance_info)
        return instances
    except Exception as e:
        return [{'error': f'Failed to list EC2 instances: {str(e)}'}]

@mcp.tool()
def create_ec2_with_s3(instance_name: str, bucket_name: str) -> Dict:
    """Create an EC2 instance and attach an S3 bucket with appropriate IAM role"""
    try:
        # Create IAM role for EC2 to access S3
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        role_name = f"EC2S3Access_{instance_name}"
        
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy)
            )
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"Role {role_name} already exists")
            
        # Attach S3 access policy
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess'
        )
        
        # Create instance profile and add role to it
        try:
            iam.create_instance_profile(InstanceProfileName=role_name)
            iam.add_role_to_instance_profile(
                InstanceProfileName=role_name,
                RoleName=role_name
            )
        except iam.exceptions.EntityAlreadyExistsException:
            print(f"Instance profile {role_name} already exists")
            
        # Create S3 bucket
        try:
            s3.create_bucket(Bucket=bucket_name)
            print(f"Created S3 bucket: {bucket_name}")
        except s3.exceptions.BucketAlreadyExists:
            print(f"Bucket {bucket_name} already exists")
        except Exception as e:
            print(f"Error creating bucket: {e}")
            
        # Get the default VPC
        vpcs = ec2.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        
        # Get subnet in the default VPC
        subnets = ec2.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        subnet_id = subnets['Subnets'][0]['SubnetId']
        
        # Create security group
        sg_name = f"ec2_s3_access_{instance_name}"
        try:
            sg = ec2.create_security_group(
                GroupName=sg_name,
                Description='Security group for EC2 with S3 access'
            )
            sg_id = sg['GroupId']
            
            # Add inbound rules
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    }
                ]
            )
        except ec2.exceptions.ClientError as e:
            if 'already exists' in str(e):
                sgs = ec2.describe_security_groups(GroupNames=[sg_name])
                sg_id = sgs['SecurityGroups'][0]['GroupId']
            else:
                raise e
        
        # Launch EC2 instance
        response = ec2.run_instances(
            ImageId='ami-0fc5d935ebf8bc3bc',  # Amazon Linux 2023
            InstanceType='t2.micro',
            MinCount=1,
            MaxCount=1,
            SecurityGroupIds=[sg_id],
            SubnetId=subnet_id,
            IamInstanceProfile={'Name': role_name},
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': instance_name},
                        {'Key': 'S3Bucket', 'Value': bucket_name}
                    ]
                }
            ]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        
        # Wait for instance to be running
        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        return {
            "status": "success",
            "instance_id": instance_id,
            "bucket_name": bucket_name,
            "message": f"Successfully created EC2 instance {instance_id} with access to S3 bucket {bucket_name}"
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
