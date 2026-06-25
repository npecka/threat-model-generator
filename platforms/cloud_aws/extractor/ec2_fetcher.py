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

                instances.append({
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
                })

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
