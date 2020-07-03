import http.client
import json
import logging
import time
import urllib.parse
import uuid

import boto3
from OpenSSL.crypto import TYPE_RSA, PKey, X509Req, dump_certificate_request, load_certificate
from OpenSSL.SSL import FILETYPE_PEM

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ACMPCA_TAG = 'ACMPCA_ARN'


def create_csr(subject):
    key = PKey()
    key.generate_key(TYPE_RSA, 2048)

    req = X509Req()
    req.get_subject().CN = subject.CN
    req.get_subject().O = subject.O  # noqa: E741
    req.get_subject().OU = subject.OU
    req.get_subject().L = subject.L
    req.get_subject().ST = subject.ST
    req.get_subject().C = subject.C
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    csr = dump_certificate_request(FILETYPE_PEM, req)
    return csr


def get_certificate(ca_arn, cert_arn):
    try:
        acm_pca = boto3.client('acm-pca')
        cert = acm_pca.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=cert_arn)
        return cert['Certificate']
    except acm_pca.exceptions.RequestInProgressException:
        logger.info('certificate %s is in progress' % cert_arn)
        time.sleep(1)
        return get_certificate(ca_arn, cert_arn)


def register_ca(ca_arn):
    acm_pca = boto3.client('acm-pca')
    iot = boto3.client('iot')
    reg_code = iot.get_registration_code()['registrationCode']
    ca_cert_pem = acm_pca.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)['Certificate']
    ca_cert = load_certificate(FILETYPE_PEM, ca_cert_pem)
    ca_cert.get_subject().CN = reg_code
    csr = create_csr(ca_cert.get_subject())
    verification_cert_arn = acm_pca.issue_certificate(
        CertificateAuthorityArn=ca_arn,
        Csr=csr,
        SigningAlgorithm='SHA256WITHRSA',
        Validity={'Value': 15, 'Type': 'YEARS'},
    )['CertificateArn']
    verification_cert_pem = get_certificate(ca_arn, verification_cert_arn)
    iot_ca_arn = iot.register_ca_certificate(
        caCertificate=ca_cert_pem, verificationCertificate=verification_cert_pem, setAsActive=True
    )['certificateArn']
    # tag ca_arn for update/delete purpose
    iot.tag_resource(resourceArn=iot_ca_arn, tags=[{'Key': ACMPCA_TAG, 'Value': ca_arn}])
    return iot_ca_arn


def delete_ca(ca_arn):
    iot = boto3.client('iot')
    # TODO: handle multiple page of CAs and Tags
    ca_certs = iot.list_ca_certificates()
    for cert in ca_certs['certificates']:
        response = iot.list_tags_for_resource(resourceArn=cert['certificateArn'])
        for tag in response['tags']:
            if tag['Key'] == ACMPCA_TAG and tag['Value'] == ca_arn:
                iot.update_ca_certificate(certificateId=cert['certificateId'], newStatus='INACTIVE')
                iot.delete_ca_certificate(certificateId=cert['certificateId'])
                break


def send_response(request, response, status=None, reason=None):
    """ Send our response to the pre-signed URL supplied by CloudFormation
    If no ResponseURL is found in the request, there is no place to send a
    response. This may be the case if the supplied event was for testing.
    """

    if status is not None:
        response['Status'] = status

    if reason is not None:
        response['Reason'] = reason

    logger.info((json.dumps(response)))

    if 'ResponseURL' in request and request['ResponseURL']:
        url = urllib.parse.urlparse(request['ResponseURL'])
        body = json.dumps(response)
        https = http.client.HTTPSConnection(url.hostname)
        https.request('PUT', url.path + '?' + url.query, body)

    return response


def cf_handler(event, context):
    response = {
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Status': 'SUCCESS',
        'Data': {},
    }
    # PhysicalResourceId is meaningless here, but CloudFormation requires it
    if 'PhysicalResourceId' in event:
        response['PhysicalResourceId'] = event['PhysicalResourceId']
    else:
        uuid_val = str(uuid.uuid4())
        response['PhysicalResourceId'] = uuid_val
        event['PhysicalResourceId'] = uuid_val
    try:
        response_data = {}
        request_type = event['RequestType']
        ca_arn = event['ResourceProperties']['CAArn']
        if request_type == 'Create':
            logger.info('Create stack event. event %s', json.dumps(event))
            iot_ca_arn = register_ca(ca_arn)
            response_data['arn'] = iot_ca_arn
        elif request_type == 'Update':
            logger.info('Update stack event. event %s', json.dumps(event))
            old_ca_arn = event['OldResourceProperties'].get('CAArn')
            if old_ca_arn and old_ca_arn != ca_arn:
                delete_ca(old_ca_arn)
                iot_ca_arn = register_ca(ca_arn)
                response_data['arn'] = iot_ca_arn
        elif request_type == 'Delete':
            logger.info('Delete stack event. event %s', json.dumps(event))
            delete_ca(ca_arn)
        response['Reason'] = 'Success'
    except Exception as e:
        logger.error('Fail to run custom resource. event: %s, error: %s', json.dumps(event), str(e))
        response['Status'] = 'FAILED'
        response['Reason'] = str(e)
    return send_response(event, response)
