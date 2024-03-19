import base64
import json
from cryptography.fernet import Fernet
import flask
import requests
import cryptography
import hashlib

import key_management
import settings

app = flask.Flask(__name__)
key = key_management.load_key()
fernet = Fernet(key)

def register_client():
    try:
        client_id = open('auth_server_client_id.txt', 'r').read()
        client_secret = open('auth_server_client_secret.txt', 'r').read()
        print('found secrets')
    except Exception:
        resp = requests.post(
            f'https://{settings.oauth_provider}/register',
            verify=settings.provider_cert
        )

        client_id = resp.json()['client_id']
        client_secret = resp.json()['client_secret']

        with open('auth_server_client_id.txt', 'w') as client_id_f:
            client_id_f.write(client_id)

        with open('auth_server_client_secret.txt', 'w') as client_secret_f:
            client_secret_f.write(client_secret)

        print('registered new secrets')

    return client_id, client_secret

@app.route('/login', methods=['post'])
def login():
    client_id, client_secret = register_client()

    cred = flask.request.json

    resp = requests.post(
        f'https://{settings.oauth_provider}/authorize',
        data=cred,
        verify=settings.provider_cert
    )

    print(f'Got authorized: {resp.json()}')

    get_tok_json = {
        'client_id': client_id,
        'client_secret': client_secret,
        'auth_code': resp.json()['auth_token'],
    }

    resp = requests.post(
        f'https://{settings.oauth_provider}/token',
        data=get_tok_json,
        verify=settings.provider_cert
    )

    if resp.status_code != 200:
        print(f'Couldnt get a token')
        return flask.jsonify({
            'auth': 'fail',
            'token': '',
        })

    print(f'Got token {resp.json()["token"]}')
    enc_tok_b = fernet.encrypt(
        resp.json()['token'].encode()
    )

    resp_json = {
        'auth': 'success',
        'token': enc_tok_b.decode(),
    }

    resp_str_b = json.dumps(resp_json).encode()
    password_hash_b = hashlib.sha256(cred['password'].encode()).digest()
    enc_json_b = key_management.aes256_cbc_encrypt(resp_str_b, password_hash_b)

    return base64.b64encode(enc_json_b).decode()

if __name__ == '__main__':
    app.run(port=settings.auth_server.split(':')[1], ssl_context=(settings.auth_server_cert, settings.auth_server_key))
