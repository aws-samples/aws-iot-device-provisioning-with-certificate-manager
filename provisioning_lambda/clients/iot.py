import json
import logging
from http import HTTPStatus

import boto3
import botocore
from botocore.exceptions import ClientError


class IotException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def check_response(func):
    def wrap(*args):
        try:
            return func(*args)
        except botocore.exceptions.ClientError as error:
            args[0].logger.error(
                '%s request failure. args: %s, response: %s',
                func.__name__, args, json.dumps(error)
            )
            raise IotException('Request failure')
    return wrap


class Iot:
    def __init__(self):
        self.client = boto3.client('iot')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

    @check_response
    def create_thing_group(self, group_name):
        response = self.client.create_thing_group(thingGroupName=group_name)
        self.logger.info('Create thing group: %s', group_name)
        return response

    @check_response
    def create_thing(self, thing_name):
        try:
            response = self.client.create_thing(thingName=thing_name)
            self.logger.info('Create thing: %s', thing_name)
        except self.client.exceptions.ResourceAlreadyExistsException as e:
            self.logger.warning('Fail to create iot thing %s, error: %s', thing_name, str(e))
            self.delete_thing(thing_name)
            response = self.client.create_thing(thingName=thing_name)
        return response

    @check_response
    def add_thing_to_thing_group(self, group_name, thing_name):
        response = self.client.add_thing_to_thing_group(thingGroupName=group_name, thingName=thing_name)
        self.logger.info('Add thing %s to group %s', thing_name, group_name)
        return response

    @check_response
    def attach_certificate(self, thing_name, cert_arn):
        response = self.client.attach_thing_principal(thingName=thing_name, principal=cert_arn)
        self.logger.info('Attach certificate %s to thing %s', cert_arn, thing_name)
        return response

    @check_response
    def attach_policy(self, policy_name, cert_arn):
        response = self.client.attach_policy(policyName=policy_name, target=cert_arn)
        self.logger.info('Attach policy %s to certificate %s', policy_name, cert_arn)
        return response

    @check_response
    def create_policy(self, policy_name, thing_arn, dsn):
        client_arn = ':'.join(thing_arn.split(':')[:-1] + ['client/%s' % dsn])
        policy_template = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': [
                        'iot:DescribeJobExecution',
                        'iot:GetPendingJobExecutions',
                        'iot:UpdateJobExecution',
                        'iot:StartNextPendingJobExecution',
                        'iot:DeleteThingShadow',
                        'iot:UpdateThingShadow',
                        'iot:GetThingShadow',
                    ],
                    'Resource': thing_arn,
                },
                {'Effect': 'Allow', 'Action': 'iot:Connect', 'Resource': client_arn},
            ],
        }
        response = self.client.create_policy(policyName=policy_name, policyDocument=json.dumps(policy_template))
        self.logger.info('Create policy: %s', policy_name)
        return response

    @check_response
    def delete_thing(self, thing_name):
        self.logger.info('Delete IoT Thing %s', thing_name)
        try:
            response = self.client.list_thing_principals(thingName=thing_name)
        except self.client.exceptions.ResourceNotFoundException:
            self.logger.warning('Thing %s does not exist.', thing_name)
        else:
            for principal in response['principals']:
                self.client.detach_thing_principal(thingName=thing_name, principal=principal)
        return self.client.delete_thing(thingName=thing_name)

    def delete_policy_versions(self, policy_name):
        response = self.client.list_policy_versions(policyName=policy_name)
        for pv in response['policyVersions']:
            if pv['isDefaultVersion'] is False:
                self.client.delete_policy_version(policyName=policy_name, policyVersionId=pv['versionId'])

    def disable_legacy_certificate(self, thing_name):
        try:
            response = self.client.list_thing_principals(thingName=thing_name)
        except self.client.exceptions.ResourceNotFoundException:
            self.logger.debug('Thing %s does not exist.', thing_name)
        else:
            for principal in response['principals']:
                policies = self.client.list_attached_policies(target=principal, recursive=False)['policies']
                for policy in policies:
                    policy_name = policy['policyName']
                    self.client.detach_policy(policyName=policy_name, target=principal)
                    self.delete_policy_versions(policy_name)
                    self.client.delete_policy(policyName=policy_name)
                cert_id = principal.split('/')[-1]
                self.client.update_certificate(certificateId=cert_id, newStatus='INACTIVE')
                self.client.detach_thing_principal(thingName=thing_name, principal=principal)

    def register_certificate(self, cert_pem, ca_cert_pem):
        try:
            response = self.client.register_certificate(
                certificatePem=cert_pem, caCertificatePem=ca_cert_pem, setAsActive=True
            )
            return response['certificateArn']
        except ClientError as e:
            self.logger.error('Fail to register certificate %s', str(e))
            raise IotException('Fail to register certificate')

    def register_iot_thing(self, dsn, cert_pem, ca_cert_pem, config):
        thing_name = '%s_%s' % (config['thingPrefix'], dsn)
        policy_name = '%s_policy' % thing_name

        self.disable_legacy_certificate(thing_name)
        cert_arn = self.register_certificate(cert_pem, ca_cert_pem)
        self.create_thing_group(config['thingGroup'])
        thing_arn = self.create_thing(thing_name)['thingArn']
        self.add_thing_to_thing_group(config['thingGroup'], thing_name)
        self.create_policy(policy_name, thing_arn, dsn)
        self.attach_certificate(thing_name, cert_arn)
        self.attach_policy(policy_name, cert_arn)
        return {'thingName': thing_name, 'certificateArn': cert_arn, 'policyName': policy_name}
