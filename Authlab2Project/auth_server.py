import base64
import json
from cryptography.fernet import Fernet
import flask
import requests
import hashlib
import logging
from functools import wraps

import key_management
import settings

app = flask.Flask(__name__)

logging.basicConfig(level=logging.INFO)

def log_post_data(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask.request.method == 'POST':
            app.logger.info('POST request data: %s', flask.request.get_data(as_text=True))
        return f(*args, **kwargs)
    return decorated_function

key = key_management.load_key()
fernet = Fernet(key)

def register_client():
    try:
        client_id = open(settings.auth_client_id, 'r').read()
        client_secret = open(settings.auth_client_secret, 'r').read()
        print('found secrets')
    except Exception:
        resp = requests.post(
            f'https://{settings.oauth_provider}/register',
            verify=settings.provider_cert
        )

        client_id = resp.json()['client_id']
        client_secret = resp.json()['client_secret']

        with open(settings.auth_client_id, 'w') as client_id_f:
            client_id_f.write(client_id)

        with open(settings.auth_client_secret, 'w') as client_secret_f:
            client_secret_f.write(client_secret)

        print('registered new secrets')

    return client_id, client_secret

@app.route('/login', methods=['post'])
@log_post_data
def login():
    try:
        client_id, client_secret = register_client()
    except Exception:
        return flask.jsonify({
            'auth': 'fail',
            'token': '',
            'message': 'failed to register client'
        })

    cred = flask.request.json

    auth_resp = requests.post(
        f'https://{settings.oauth_provider}/authorize',
        data=cred,
        verify=settings.provider_cert
    )

    auth_resp_json = auth_resp.json()

    if auth_resp_json['status'] == 'error':
        return flask.jsonify({
            'auth': 'fail',
            'token': '',
            'message': auth_resp_json['message']
        })

    get_tok_json = {
        'client_id': client_id,
        'client_secret': client_secret,
        'auth_code': auth_resp_json['auth_code'],
    }

    tok_resp = requests.post(
        f'https://{settings.oauth_provider}/token',
        data=get_tok_json,
        verify=settings.provider_cert
    )

    tok_resp_json = tok_resp.json()

    if tok_resp_json['status'] == 'error':
        print(f'Couldnt get a token')
        return flask.jsonify({
            'auth': 'fail',
            'token': '',
            'message': tok_resp_json['message']
        })

    print(f'Got token {tok_resp_json["token"]}')
    enc_tok_b = fernet.encrypt(
        tok_resp_json['token'].encode()
    )

    #resp_str_b = json.dumps(resp_json).encode()
    password_hash_b = hashlib.sha256(cred['password'].encode()).digest()
    enc_enc_tok_b = key_management.aes256_cbc_encrypt(enc_tok_b, password_hash_b)

    print(enc_enc_tok_b)

    return flask.jsonify({
        'auth': 'success',
        'token': base64.b64encode(enc_enc_tok_b).decode()
    })

if __name__ == '__main__':
    app.run(port=settings.auth_server.split(':')[1], ssl_context=(settings.auth_server_cert, settings.auth_server_key))
