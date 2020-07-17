import base64
import json
import logging
import socket
from http import HTTPStatus

import boto3


API_NAME = 'IoTProvisioning'


def parse_apig_paginator(paginator, next_token=None):
    if next_token:
        response_iterator = paginator.paginate(
            PaginationConfig={'StartingToken': next_token}
        )
    else:
        response_iterator = paginator.paginate()
    token = None
    for resp in response_iterator:
        for item in resp['items']:
            if item['name'] == API_NAME:
                return True, item['id']
        if 'position' in resp:
            token = resp['position']
    return False, token


def invoke_certificate_api(api_id, resource_id, device_public_key):
    logging.info('Retrieving provisioning profile for device')
    apig = boto3.client('apigateway')
    resp = apig.test_invoke_method(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod='POST',
        body=json.dumps({'DSN': 'test', 'publicKey': device_public_key})
    )
    status = resp['ResponseMetadata'].get('HTTPStatusCode')
    if status != HTTPStatus.OK.value:
        logging.error('request fail')
        return

    return resp['body']


def main():
    # Get api id
    apig = boto3.client('apigateway')
    paginator = apig.get_paginator('get_rest_apis')
    is_match, token = parse_apig_paginator(paginator)
    while not is_match and token:
        is_match, token = parse_apig_paginator(paginator, token)
    if not is_match and not token:
        logging.error('Cannot find api %s', API_NAME)
        return
    api_id = token

    # Get api resource
    resource_id = None
    resp = apig.get_resources(restApiId=api_id)
    for item in resp['items']:
        if item['path'] == '/certificate':
            resource_id = item['id']
    if not resource_id:
        logging.error('Cannot find api resource')
        return

    logging.info('Trying to connect...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        addr = ('127.0.0.1', 65432)
        s.connect(addr)
        data = s.recv(1024)
        device_public_key = base64.b64encode(data).decode('ascii')
        resp = invoke_certificate_api(api_id, resource_id, device_public_key)
        if not resp:
            logger.error('Fail to request the provisioning API')
        else:
            logging.info('Send provisioning profile to device')        
            s.sendto(resp.encode('ascii'), addr)
    logging.info('Finish')


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    main()
