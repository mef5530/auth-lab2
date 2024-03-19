import sqlite3
import flask
import secrets
import logging
from functools import wraps

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

def create_tables():
    connection = sqlite3.connect(settings.provider_database)
    cursor = connection.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            client_secret TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS authorizations (
            authorization_code TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tokens (
            access_token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')

    #cursor.execute('INSERT INTO users (username, password) VALUES (?,?);', ('alice', 'password1'))

    connection.commit()
    connection.close()

    print("Database and tables created.")

def get_conn():
    conn = sqlite3.connect(settings.provider_database)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['POST'])
@log_post_data
def register():
    client_id = secrets.token_hex(8)
    client_secret = secrets.token_hex(16)

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO clients (client_id, client_secret) VALUES (?,?);', (client_id, client_secret))
    cursor.close()
    conn.commit()
    conn.close()

    print(f'Registered {client_id}, {client_secret}')

    return flask.jsonify({
        'client_id': client_id,
        'client_secret': client_secret
    })


@app.route('/authorize', methods=['POST'])
@log_post_data
def authorize():
    username = flask.request.form['username']
    password = flask.request.form['password']

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?;', (username,))
    user = cursor.fetchone()

    if user and user['password'] == password:
        auth_code = secrets.token_hex(8)
        cursor.execute('INSERT INTO authorizations (authorization_code, username) VALUES (?,?);', (auth_code, username))

        cursor.close()
        conn.commit()
        conn.close()

        print(f'Authorized {auth_code}, {username}, {password}')

        return flask.jsonify({
            'status': 'success',
            'auth_code': auth_code
        })
    else:
        cursor.close()
        conn.commit()
        conn.close()

        return flask.jsonify({
            'status': 'error',
            'message': 'auth code generation failed'
        })

@app.route('/token', methods=['POST'])
@log_post_data
def token():
    auth_code = flask.request.form.get('auth_code')
    client_id = flask.request.form.get('client_id')
    client_secret = flask.request.form.get('client_secret')

    conn = get_conn()
    cursor = conn.cursor()


    cursor.execute('SELECT * FROM clients WHERE client_id = ?;', (client_id,))
    client = cursor.fetchone()

    if client and client['client_secret'] == client_secret:
        cursor.execute('SELECT * FROM authorizations WHERE authorization_code = ?;', (auth_code,))
        auth = cursor.fetchone()

        cursor.execute('SELECT * FROM authorizations')

        if auth:
            tok = secrets.token_hex(16)
            cursor.execute('INSERT INTO tokens (access_token, username) VALUES (?,?);', (tok, auth['username']))
            cursor.execute('DELETE FROM authorizations WHERE authorization_code = ?;', (auth_code,))

            cursor.close()
            conn.commit()
            conn.close()

            print(f'Created token {tok}, {auth_code}, {client_id}, {client_secret}')

            return flask.jsonify({
                'status': 'success',
                'token': tok
            })
        else:
            cursor.close()
            conn.commit()
            conn.close()

            return flask.jsonify({
                'status': 'error',
                'message': 'failed to create token'
            })

@app.route('/validate', methods=['POST'])
@log_post_data
def validate():
    tok = flask.request.form.get('token')
    username = flask.request.form.get('username')

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM tokens WHERE (access_token = ?) AND (username = ?);', (tok, username))
    if len(cursor.fetchall()) >= 1:
        print(f'Validated token {tok}, {username}')
        return flask.jsonify({
            'status': 'success',
            'message': 'validation was successful'
        })
    else:
        return flask.jsonify({
            'status': 'error',
            'message': 'token is not valid'
        })

if __name__ == '__main__':
    create_tables()
    app.run(port=settings.oauth_provider.split(':')[1], ssl_context=(settings.provider_cert, settings.provider_key))