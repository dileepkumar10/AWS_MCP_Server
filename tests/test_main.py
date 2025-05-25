import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
import boto3
from AWS_MCP_Server.main import create_ec2_instance, delete_ec2_instance, detect_account_type

@pytest.fixture
def mock_ec2():
    with patch('boto3.client') as mock_client:
        ec2_mock = MagicMock()
        mock_client.return_value = ec2_mock
        yield ec2_mock

def test_create_ec2_instance_success(mock_ec2):
    # Mock responses
    mock_ec2.describe_images.return_value = {
        'Images': [{'ImageId': 'ami-123', 'CreationDate': '2023-01-01'}]
    }
    mock_ec2.describe_vpcs.return_value = {'Vpcs': [{'VpcId': 'vpc-123'}]}
    mock_ec2.create_security_group.return_value = {'GroupId': 'sg-123'}
    mock_ec2.run_instances.return_value = {
        'Instances': [{'InstanceId': 'i-123', 'State': {'Name': 'running'}}]
    }
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-123',
                'PublicIpAddress': '1.2.3.4',
                'State': {'Name': 'running'}
            }]
        }]
    }

    result = create_ec2_instance('t2.micro')
    assert result['InstanceId'] == 'i-123'
    assert result['PublicIpAddress'] == '1.2.3.4'
    assert result['State'] == 'running'

def test_delete_ec2_instance_success(mock_ec2):
    # Mock responses
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-123',
                'SecurityGroups': [{'GroupId': 'sg-123'}]
            }]
        }]
    }

    result = delete_ec2_instance('i-123')
    assert result['status'] == 'success'
    assert 'i-123' in result['message']

def test_detect_account_type_free_tier():
    with patch('main.get_monthly_spend') as mock_spend:
        mock_spend.return_value = 10.0
        with patch('boto3.client') as mock_client:
            mock_org = MagicMock()
            mock_org.describe_organization.return_value = {}
            mock_client.return_value = mock_org
            
            result = detect_account_type()
            assert "Free Tier" in result
