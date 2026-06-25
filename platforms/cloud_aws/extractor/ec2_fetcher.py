#!/usr/bin/env python3
"""
AWS EC2 Metadata Fetcher
Collects EC2 instance details, security groups, IAM roles
"""

import boto3
import json
from datetime import datetime


def get_ec2_instances(region='us-east-1'):
    """Get all supply chain EC2 instances"""
    ec2 = boto3.client('ec2', region_name=region)

    instances = []

    try:
        response = ec2.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': ['running', 'pending']
                }
            ]
        )

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                # Get instance name from tags
                name = ''
                zone = ''
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                    elif tag['Key'] == 'Zone':
                        zone = tag['Value']

                instance_data = {
                    'id': instance['InstanceId'],
                    'name': name,
                    'zone': zone,
                    'instance_type': instance['InstanceType'],
                    'public_ip': instance.get('PublicIpAddress', ''),
                    'private_ip': instance.get('PrivateIpAddress', ''),
                    'vpc_id': instance.get('VpcId', ''),
                    'subnet_id': instance.get('SubnetId', ''),
                    'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])],
                    'iam_instance_profile': instance.get('IamInstanceProfile', {}).get('Arn', ''),
                    'state': instance['State']['Name'],
                    'launch_time': instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else '',
                    'user_data': '',
                    'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                }

                # Fetch user-data separately (requires additional API call)
                try:
                    user_data_response = ec2.describe_instance_attribute(
                        InstanceId=instance['InstanceId'],
                        Attribute='userData'
                    )
                    if 'UserData' in user_data_response and 'Value' in user_data_response['UserData']:
                        import base64
                        user_data_b64 = user_data_response['UserData']['Value']
                        user_data_decoded = base64.b64decode(user_data_b64).decode('utf-8', errors='ignore')
                        instance_data['user_data'] = user_data_decoded
                except Exception as e:
                    # User-data may not exist or may not be accessible
                    pass

                instances.append(instance_data)

        print(f"  ✓ Found {len(instances)} EC2 instances")

    except Exception as e:
        print(f"  ✗ Error fetching EC2 instances: {e}")

    return instances


def get_security_groups(region='us-east-1', group_ids=None):
    """Get security group details"""
    ec2 = boto3.client('ec2', region_name=region)

    security_groups = []

    try:
        if group_ids:
            response = ec2.describe_security_groups(GroupIds=group_ids)
        else:
            response = ec2.describe_security_groups(
                Filters=[
                    {
                        'Name': 'tag:Project',
                        'Values': ['supply-chain-threat-model']
                    }
                ]
            )

        for sg in response['SecurityGroups']:
            security_groups.append({
                'id': sg['GroupId'],
                'name': sg['GroupName'],
                'description': sg['Description'],
                'vpc_id': sg['VpcId'],
                'ingress_rules': [
                    {
                        'protocol': rule.get('IpProtocol', ''),
                        'from_port': rule.get('FromPort', ''),
                        'to_port': rule.get('ToPort', ''),
                        'cidr_blocks': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                        'source_groups': [sg['GroupId'] for sg in rule.get('UserIdGroupPairs', [])],
                    }
                    for rule in sg.get('IpPermissions', [])
                ],
                'egress_rules': [
                    {
                        'protocol': rule.get('IpProtocol', ''),
                        'from_port': rule.get('FromPort', ''),
                        'to_port': rule.get('ToPort', ''),
                        'cidr_blocks': [ip['CidrIp'] for ip in rule.get('IpRanges', [])],
                    }
                    for rule in sg.get('IpPermissionsEgress', [])
                ],
            })

        print(f"  ✓ Collected {len(security_groups)} security groups")

    except Exception as e:
        print(f"  ✗ Error fetching security groups: {e}")

    return security_groups


def get_iam_roles(region='us-east-1', instance_profile_arns=None):
    """Get IAM role details for instances"""
    iam = boto3.client('iam')

    roles = []

    try:
        if instance_profile_arns:
            for arn in instance_profile_arns:
                if not arn:
                    continue

                # Extract profile name from ARN
                profile_name = arn.split('/')[-1]

                try:
                    profile = iam.get_instance_profile(InstanceProfileName=profile_name)

                    for role in profile['InstanceProfile']['Roles']:
                        role_name = role['RoleName']

                        # Get role policies
                        inline_policies = []
                        try:
                            policies_response = iam.list_role_policies(RoleName=role_name)
                            for policy_name in policies_response['PolicyNames']:
                                policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                                inline_policies.append({
                                    'name': policy_name,
                                    'document': policy['PolicyDocument']
                                })
                        except Exception as e:
                            print(f"    Warning: Could not get inline policies for {role_name}: {e}")

                        # Get attached managed policies
                        attached_policies = []
                        try:
                            attached_response = iam.list_attached_role_policies(RoleName=role_name)
                            attached_policies = [
                                {'name': p['PolicyName'], 'arn': p['PolicyArn']}
                                for p in attached_response['AttachedPolicies']
                            ]
                        except Exception as e:
                            print(f"    Warning: Could not get attached policies for {role_name}: {e}")

                        roles.append({
                            'name': role_name,
                            'arn': role['Arn'],
                            'instance_profile': profile_name,
                            'inline_policies': inline_policies,
                            'attached_policies': attached_policies,
                        })

                except Exception as e:
                    print(f"    Warning: Could not get instance profile {profile_name}: {e}")

        print(f"  ✓ Collected {len(roles)} IAM roles")

    except Exception as e:
        print(f"  ✗ Error fetching IAM roles: {e}")

    return roles


def get_s3_buckets(region='us-east-1'):
    """Get S3 bucket details including public access settings"""
    s3 = boto3.client('s3', region_name=region)

    buckets = []

    try:
        # List all buckets
        response = s3.list_buckets()

        for bucket in response.get('Buckets', []):
            bucket_name = bucket['Name']

            bucket_info = {
                'name': bucket_name,
                'creation_date': bucket.get('CreationDate', '').isoformat() if bucket.get('CreationDate') else '',
                'public_access_block': {},
                'policy': None,
            }

            # Get public access block configuration
            try:
                pub_access = s3.get_public_access_block(Bucket=bucket_name)
                if 'PublicAccessBlockConfiguration' in pub_access:
                    bucket_info['public_access_block'] = pub_access['PublicAccessBlockConfiguration']
            except:
                # No public access block configured (means it might be public)
                bucket_info['public_access_block'] = {
                    'block_public_acls': False,
                    'block_public_policy': False,
                    'ignore_public_acls': False,
                    'restrict_public_buckets': False
                }

            # Get bucket policy
            try:
                policy_response = s3.get_bucket_policy(Bucket=bucket_name)
                if 'Policy' in policy_response:
                    import json
                    bucket_info['policy'] = json.loads(policy_response['Policy'])
            except:
                # No bucket policy
                pass

            buckets.append(bucket_info)

        print(f"  ✓ Collected {len(buckets)} S3 buckets")

    except Exception as e:
        print(f"  ✗ Error fetching S3 buckets: {e}")

    return buckets


def get_iam_users(region='us-east-1'):
    """Get IAM user details including MFA status"""
    iam = boto3.client('iam', region_name=region)

    users = []

    try:
        # List all IAM users
        response = iam.list_users()

        for user in response.get('Users', []):
            user_name = user['UserName']

            user_info = {
                'name': user_name,
                'arn': user.get('Arn', ''),
                'user_id': user.get('UserId', ''),
                'create_date': user.get('CreateDate', '').isoformat() if user.get('CreateDate') else '',
                'password_last_used': user.get('PasswordLastUsed', '').isoformat() if user.get('PasswordLastUsed') else '',
                'mfa_enabled': False,
                'mfa_devices': [],
                'access_keys': [],
                'attached_policies': []
            }

            # Check MFA devices
            try:
                mfa_response = iam.list_mfa_devices(UserName=user_name)
                mfa_devices = mfa_response.get('MFADevices', [])
                user_info['mfa_devices'] = [
                    {
                        'serial_number': device.get('SerialNumber', ''),
                        'enable_date': device.get('EnableDate', '').isoformat() if device.get('EnableDate') else ''
                    }
                    for device in mfa_devices
                ]
                user_info['mfa_enabled'] = len(mfa_devices) > 0
            except:
                pass

            # Get access keys
            try:
                keys_response = iam.list_access_keys(UserName=user_name)
                user_info['access_keys'] = [
                    {
                        'access_key_id': key.get('AccessKeyId', ''),
                        'status': key.get('Status', ''),
                        'create_date': key.get('CreateDate', '').isoformat() if key.get('CreateDate') else ''
                    }
                    for key in keys_response.get('AccessKeyMetadata', [])
                ]
            except:
                pass

            # Get attached policies
            try:
                policies_response = iam.list_attached_user_policies(UserName=user_name)
                user_info['attached_policies'] = [
                    {
                        'policy_name': policy.get('PolicyName', ''),
                        'policy_arn': policy.get('PolicyArn', '')
                    }
                    for policy in policies_response.get('AttachedPolicies', [])
                ]
            except:
                pass

            users.append(user_info)

        print(f"  ✓ Collected {len(users)} IAM users")

    except Exception as e:
        print(f"  ✗ Error fetching IAM users: {e}")

    return users


def get_vpc_details(region='us-east-1', vpc_id=None):
    """Get VPC and network configuration"""
    ec2 = boto3.client('ec2', region_name=region)

    vpc_info = {}

    try:
        if vpc_id:
            vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])['Vpcs']
        else:
            vpcs = ec2.describe_vpcs(
                Filters=[
                    {
                        'Name': 'tag:Project',
                        'Values': ['supply-chain-threat-model']
                    }
                ]
            )['Vpcs']

        if vpcs:
            vpc = vpcs[0]
            vpc_info = {
                'id': vpc['VpcId'],
                'cidr': vpc['CidrBlock'],
                'subnets': [],
                'route_tables': [],
                'network_acls': [],
            }

            # Get subnets
            subnets = ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc['VpcId']]}]
            )['Subnets']

            vpc_info['subnets'] = [
                {
                    'id': s['SubnetId'],
                    'cidr': s['CidrBlock'],
                    'availability_zone': s['AvailabilityZone'],
                    'map_public_ip': s.get('MapPublicIpOnLaunch', False),
                }
                for s in subnets
            ]

            print(f"  ✓ Collected VPC details ({len(subnets)} subnets)")

    except Exception as e:
        print(f"  ✗ Error fetching VPC details: {e}")

    return vpc_info
