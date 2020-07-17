import base64
import json
import logging
import signal
import socket
import sys
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def signal_handler(sig, frame):
    logging.info('You pressed Ctrl+C')
    sys.exit(0)


def parse_response_data(data, local_private_key):
    try:
        logging.info('Parsing provisioning results')
        resp = json.loads(data.decode('ascii'))
        remote_public_key = X25519PublicKey.from_public_bytes(
            base64.b64decode(resp['publicKey'])
        )
        secret = local_private_key.exchange(remote_public_key)
        fernet = Fernet(base64.b64encode(secret))
        private_key = fernet.decrypt(
            resp['encryptedPrivateKey'].encode('utf-8')
        ).decode('utf-8')
        logging.info("Get device certificate: \n %s", resp['certificatePem'])
        logging.info("Get device private key: \n %s", private_key)
    except Exception:
        logging.error('Fail to parse the response from provisioning app')


def main():
    local_private_key = X25519PrivateKey.generate()
    local_public_key = local_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 65432))
        logging.info('Waitting for connection')
        s.listen()
        conn, addr = s.accept()
        with conn:
            logging.info('Connected by %s', str(addr))
            conn.sendto(local_public_key, addr)
            data = b''
            while True:
                part = conn.recv(1024)
                data += part
                if len(part) < 1024:
                    break
            parse_response_data(data, local_private_key)
            logging.info('Finish')


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    signal.signal(signal.SIGINT, signal_handler)
    main()
