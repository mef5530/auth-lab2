import cryptography.fernet
import flask
import requests
from cryptography.fernet import Fernet

import key_management
import settings

app = flask.Flask(__name__)
key = key_management.load_key()
fernet = Fernet(key)

@app.route('/validate_token', methods=['POST'])
def validate_token():
    enc_tok = flask.request.json['token']
    username = flask.request.json['username']

    try:
        dec_tok = fernet.decrypt(enc_tok.encode()).decode()
        print(f'Decrypted {enc_tok} - MAC is successful')
    except cryptography.fernet.InvalidToken:
        print('MAC failed')

        return flask.jsonify({
            'status': 'MAC failed'
        })

    resp = requests.post(
        f'https://{settings.oauth_provider}/validate',
        data={'token': dec_tok, 'username': username},
        verify=settings.provider_cert
    )

    if resp.status_code != 200:
        print(f'Provider validation failed {dec_tok}, {username}')
        return flask.jsonify({
            'status': 'validation failed'
        })

    print(f'MAC and Provider validation was successful {dec_tok}, {username}')
    return flask.jsonify({
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(port=settings.app_server.split(':')[1])