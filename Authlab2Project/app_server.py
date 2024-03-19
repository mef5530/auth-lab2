import cryptography.fernet
import flask
import requests
from cryptography.fernet import Fernet
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

@app.route('/validate_token', methods=['POST'])
@log_post_data
def validate_token():
    enc_tok = flask.request.json['token']
    username = flask.request.json['username']

    try:
        dec_tok = fernet.decrypt(enc_tok.encode()).decode()
        print(f'Decrypted {enc_tok} - MAC is successful')
    except cryptography.fernet.InvalidToken:
        print('MAC failed')

        return flask.jsonify({
            'status': 'error',
            'message': 'MAC failed'
        })

    resp = requests.post(
        f'https://{settings.oauth_provider}/validate',
        data={'token': dec_tok, 'username': username},
        verify=settings.provider_cert
    )

    resp_json = resp.json()

    if resp_json['status'] == 'error':
        print(f'Provider validation failed {dec_tok}, {username}')
        return flask.jsonify({
            'status': 'error',
            'message': 'validation failed'
        })

    print(f'MAC and Provider validation was successful {dec_tok}, {username}')

    return flask.jsonify({
        'status': 'success',
        'message': 'MAC and Provider validation was successful',
        'token': dec_tok
    })

if __name__ == '__main__':
    app.run(port=settings.app_server.split(':')[1])