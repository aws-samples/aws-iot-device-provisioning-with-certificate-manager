import logging
import time

import boto3


class IssueCertException(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class AcmPca:
    def __init__(self):
        self.client = boto3.client('acm-pca')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)

    def issue_cert(self, ca_arn, csr, validity):
        try:
            response = self.client.issue_certificate(
                CertificateAuthorityArn=ca_arn,
                Csr=csr,
                SigningAlgorithm='SHA256WITHRSA',
                Validity={'Value': validity, 'Type': 'YEARS'},
            )
            certificate_arn = response['CertificateArn']
            certificate = None
            while certificate is None:
                time.sleep(1)
                certificate = self.get_certificate(ca_arn, certificate_arn)
            return certificate_arn, certificate
        except Exception as e:
            raise IssueCertException(str(e))

    def get_certificate(self, ca_arn, certificate_arn):
        try:
            response = self.client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=certificate_arn)
            return response['Certificate']
        except self.client.exceptions.RequestInProgressException:
            self.logger.info('certificate %s is in progress', certificate_arn)
            return None

    def get_ca_certificate(self, ca_arn):
        response = self.client.get_certificate_authority_certificate(CertificateAuthorityArn=ca_arn)
        return response['Certificate']
