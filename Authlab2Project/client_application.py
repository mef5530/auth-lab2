import base64
import hashlib
import json
import flask
import requests
import settings
import logging
from functools import wraps

import key_management

app = flask.Flask(__name__)

logging.basicConfig(level=logging.INFO)

def log_post_data(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if flask.request.method == 'POST':
            app.logger.info('POST request data: %s', flask.request.get_data(as_text=True))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['POST'])
@log_post_data
def login():
    cred = {
        'username': flask.request.form['username'],
        'password': flask.request.form['password'],
    }

    resp = requests.post(
        f'https://{settings.auth_server}/login',
        json=cred,
        verify=settings.auth_server_cert
    )

    resp_json_enc = resp.json()

    if resp_json_enc['auth'] == 'fail':
        return flask.jsonify({
            'status': 'error',
            'message': resp_json_enc['message']
        })

    password_hash_b = hashlib.sha256(flask.request.form['password'].encode()).digest()
    token_b = key_management.aes256_cbc_decrypt(base64.b64decode(resp_json_enc['token'].encode()), password_hash_b)

    resp = requests.post(
        f'http://{settings.app_server}/validate_token',
        json={
            'token': token_b.decode(),
            'username': flask.request.form['username']
        }
    )

    return flask.jsonify(resp.json())

if __name__ == '__main__':
    app.run(port=settings.client_application.split(':')[1])

