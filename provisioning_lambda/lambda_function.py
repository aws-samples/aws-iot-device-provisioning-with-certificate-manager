import base64
import json
import logging
import os
import re
from http import HTTPStatus

import boto3
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from OpenSSL.crypto import TYPE_RSA, PKey, X509Req, dump_certificate_request, dump_privatekey
from OpenSSL.SSL import FILETYPE_PEM

from clients.acmpca import AcmPca, IssueCertException
from clients.iot import Iot, IotException

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class InvalidRequestException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class EnvironmentException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class ConfigError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def get_request_body(event):
    body = json.loads(event.get('body', '{}'))
    # check DSN
    if not body.get('DSN'):
        raise InvalidRequestException('Missing required field: DSN')
    elif len(body['DSN']) > 115:
        raise InvalidRequestException('The DSN must be between 1 and 115 long.')
    else:
        pattern = re.compile('[^\\w\\-]')
        if pattern.match(body['DSN']):
            raise InvalidRequestException('DSN Must contain only alphanumeric characters and/or the following: -_')
    # check public key
    if not body.get('publicKey'):
        raise InvalidRequestException('Missing required field: publicKey')
    else:
        try:
            body['publicKey'] = X25519PublicKey.from_public_bytes(
                base64.b64decode(body['publicKey'])
            )
        except Exception:
            raise InvalidRequestException('Invalid public key')
    return body


def check_env():
    if not os.environ.get('CA_ARN'):
        raise EnvironmentException('Missing CA_ARN')
    if not os.environ.get('DDB_TABLE'):
        raise EnvironmentException('Missing DDB_TABLE')
    else:
        try:
            boto3.client('dynamodb').describe_table(TableName=os.environ['DDB_TABLE'])
        except ClientError:
            raise EnvironmentException('Invalid DDB_TABLE')


def get_config():
    with open('config.json') as f:
        config = json.load(f)
    if set(config.keys()) != set(['certificate', 'iot']):
        raise ConfigError('Invalid config')
    # check certificate config
    if set(config.get('certificate', {}).keys()) != set(['subject', 'validity']):
        raise ConfigError('Invalid certificate config')
    subject = config['certificate']['subject']
    if subject.keys() != set(['CN', 'O', 'OU', 'L', 'ST', 'C']):
        raise ConfigError('Invalid certificate subject')
    for subject_key, subject_value in subject.items():
        if not type(subject_value) is str:
            raise ConfigError('Invalid certificate subject: %s' % subject_key)
    validity = config['certificate'].get('validity')
    if not type(validity) is int:
        raise ConfigError('Invalid certificate validity')
    # check iot config
    if set(config.get('iot', {}).keys()) != set(['certValidity', 'thingPrefix', 'thingGroup']):
        raise ConfigError('Invalid iot config')
    for key, value in config['iot'].items():
        if key == 'certValidity':
            if not type(value) is int:
                raise ConfigError('Invalid iot certValidity')
        elif not type(value) is str:
            raise ConfigError('Invalid iot config: %s' % key)
    return config


def create_csr_key(subject):
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    req = X509Req()
    req.get_subject().CN = subject['CN']
    req.get_subject().O = subject['O']  # noqa: E741
    req.get_subject().OU = subject['OU']
    req.get_subject().L = subject['L']
    req.get_subject().ST = subject['ST']
    req.get_subject().C = subject['C']
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    csr = dump_certificate_request(FILETYPE_PEM, req)
    privatekey = dump_privatekey(FILETYPE_PEM, key).decode('utf-8')

    return csr, privatekey


def record_device_info(dsn, cert_arn, thing_info):
    table = boto3.resource('dynamodb').Table(os.environ['DDB_TABLE'])
    item = table.get_item(Key={'dsn': dsn})
    if 'Item' not in item:
        response = table.put_item(Item={'dsn': dsn, 'certificateArn': cert_arn, 'thingInfo': thing_info})
    else:
        response = table.update_item(
            Key={'dsn': dsn},
            UpdateExpression='SET certificateArn = :certificateArn, thingInfo = :thingInfo',
            ExpressionAttributeValues={':certificateArn': cert_arn, ':thingInfo': thing_info}
        )
    if response['ResponseMetadata']['HTTPStatusCode'] != HTTPStatus.OK.value:
        logger.error('Fail to update device (%s), certificateArn (%s)', dsn, cert_arn)


def provisioning_handler(event, context):
    resp = {'statusCode': HTTPStatus.OK.value, 'body': {}}

    try:
        check_env()
        body = get_request_body(event)
        dsn = body['DSN']
        public_key = body['publicKey']
        ca_arn = os.environ['CA_ARN']
        config = get_config()

        csr, privatekey = create_csr_key(config['certificate']['subject'])
        acmpca = AcmPca()
        cert_arn, cert_pem = acmpca.issue_cert(ca_arn, csr, config['iot']['certValidity'])
        ca_cert_pem = acmpca.get_ca_certificate(ca_arn)
        thing_info = Iot().register_iot_thing(dsn, cert_pem, ca_cert_pem, config['iot'])
        record_device_info(dsn, cert_arn, thing_info)

        # generate X25519 key pair
        local_private_key = X25519PrivateKey.generate()
        local_public_key = local_private_key.public_key()
        local_public_key_str = base64.b64encode(
            local_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        ).decode('ascii')

        # generate shared key
        secret = local_private_key.exchange(public_key)

        # encrypt private key
        fernet = Fernet(base64.b64encode(secret))
        encrypted_private_key = fernet.encrypt(privatekey.encode('utf-8')).decode('utf-8')

        resp['body'] = {
            'certificatePem': cert_pem,
            'encryptedPrivateKey': encrypted_private_key,
            'publicKey': local_public_key_str
        }
    except InvalidRequestException as ire:
        logger.warning('Invalid request: %s', json.dumps(event))
        resp.update({'statusCode': HTTPStatus.BAD_REQUEST.value, 'body': {'msg': str(ire)}})
    except EnvironmentException as ire:
        logger.error('Environment error: %s', str(ire))
        resp.update(
            {
                'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR.value,
                'body': {'msg': HTTPStatus.INTERNAL_SERVER_ERROR.description},
            }
        )
    except ConfigError as ce:
        logger.error('Config error: %s', str(ce))
        resp.update(
            {
                'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR.value,
                'body': {'msg': HTTPStatus.INTERNAL_SERVER_ERROR.description},
            }
        )
    except IssueCertException as ice:
        logger.error('acm-pca issue certificate fail: %s', str(ice))
        resp.update({'statusCode': HTTPStatus.BAD_GATEWAY.value, 'body': {'msg': 'Fail to issue certificate'}})
    except IotException as ie:
        logger.error('Fail to create IoT thing on AWS IoT: %s', str(ie))
        resp.update({'statusCode': HTTPStatus.BAD_GATEWAY.value, 'body': {'msg': 'Fail to create info on IoT Core'}})
    except Exception as e:
        logger.error('Unexpected exception: %s', str(e))
        resp.update({'statusCode': HTTPStatus.INTERNAL_SERVER_ERROR.value, 'body': {'msg': 'Unknown error'}})

    resp['body'] = json.dumps(resp['body'])
    return resp
