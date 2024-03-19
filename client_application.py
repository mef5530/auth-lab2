import base64
import hashlib
import json

import flask
import requests
import settings

import key_management

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = flask.Flask(__name__)

@app.route('/login', methods=['POST'])
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

    password_hash_b = hashlib.sha256(flask.request.form['password'].encode()).digest()
    resp_decrypt_b = key_management.aes256_cbc_decrypt(base64.b64decode(resp.text), password_hash_b)

    try:
        resp_json = json.loads(resp_decrypt_b)
        resp_json['username'] = flask.request.form['username']

        print(f'Decrypted {resp_decrypt_b} using password hash')
    except json.JSONDecodeError:
        print('failed to parse json')
        return None

    requests.post(
        f'http://{settings.app_server}/validate_token',
        json=resp_json
    )

    return flask.jsonify(resp_json)

if __name__ == '__main__':
    app.run(port=settings.client_application.split(':')[1])

