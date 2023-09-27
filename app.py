from flask import Flask, request, jsonify
from functools import wraps
from cryptography.fernet import Fernet


app_db = {
    'admin_app': {
        'api_key': 'admin',
        'api_token': 'admin',
        'is_admin': True,
        'secret_keys': 
            {'admin_secret_1': Fernet.generate_key().decode('utf-8'),}
        
    },
    'test_app': {
        'api_key': 'test',
        'api_token': 'test',
        'is_admin': False,
        'secret_keys': {
            'test_secret_1': 'key2',
        }

    }
}

#authentication decorators
def normal_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('api-key')
        api_token = request.headers.get('api-token')
        if api_key is None or api_token is None:
            return jsonify({'status': 'failed', 'message': 'Authentication required'}), 401
        for app in app_db:
            if app_db[app]['api_key'] == api_key and app_db[app]['api_token'] == api_token:
                return f(*args, **kwargs)
        return jsonify({'status': 'failed', 'message': 'Authentication failed'}), 401
    return decorated

def admin_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('api-key')
        api_token = request.headers.get('api-token')
        if api_key is None or api_token is None:
            return jsonify({'status': 'failed', 'message': 'Authentication required'}), 401

        for app in app_db:
            if app_db[app]['api_key'] == api_key and app_db[app]['api_token'] == api_token:
                if app_db[app]['is_admin']==False:
                    return jsonify({'status': 'failed', 'message': 'Action requires Admin'}), 401
                return f(*args, **kwargs)
        return jsonify({'status': 'failed', 'message': 'Authentication failed'}), 401
    return decorated

def validate_app_matches_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('api-key')
        app_name = request.values.get('app-name')
        if api_key is None or app_name is None:
            return jsonify({'status': 'failed', 'message': 'Authentication required'}), 401
        for app in app_db:
            if app_db[app]['api_key'] == api_key and app == app_name:
                return f(*args, **kwargs)
        return jsonify({'status': 'failed', 'message': 'Authentication failed'}), 401

        return f(*args, **kwargs)
    return decorated

app = Flask(__name__)


@app.route('/encrypt', methods=['POST'])
@normal_auth
@validate_app_matches_key
def encrypt():
    """
    Encrypts data using secret key of app

    @param app-name: name of app to be created
    @param secret-key-name: name of secret key to be created
    @param data: data to be encrypted
    """
    app_name = request.values.get('app-name')
    key_name = request.values.get('secret-key-name')
    data = request.values.get('data')
    if app_name is None:
        return jsonify({'status': 'failed', 'message': 'App name required'}), 400
    if app_name not in app_db:
        return jsonify({'status': 'failed', 'message': 'App does not exist'}), 400
    if key_name not in app_db[app_name]['secret_keys']:
        return jsonify({'status': 'failed', 'message': 'Secret key does not exist'}), 400
    if data is None:
        return jsonify({'status': 'failed', 'message': 'Data required'}), 400
    
    fernet = Fernet(app_db[app_name]['secret_keys'][key_name])
    data = data.encode('utf-8')
    encrypted_data =fernet.encrypt(data)
    return jsonify({'status': 'success', 'data': encrypted_data.decode('utf-8')})


@app.route('/decrypt', methods=['POST'])
@normal_auth
@validate_app_matches_key
def decrypt():
    """
    Decrypts data using secret key of app

    @param app-name: name of app to be created
    @param secret-key-name: name of secret key to be created
    @param data: data to be decrypted
    """
    app_name = request.values.get('app-name')
    key_name = request.values.get('secret-key-name')
    data = request.values.get('data')
    if app_name is None:
        return jsonify({'status': 'failed', 'message': 'App name required'}), 400
    if app_name not in app_db:
        return jsonify({'status': 'failed', 'message': 'App does not exist'}), 400
    if key_name not in app_db[app_name]['secret_keys']:
        return jsonify({'status': 'failed', 'message': 'Secret key does not exist'}), 400
    if data is None:
        return jsonify({'status': 'failed', 'message': 'Data required'}), 400
    
    key = app_db[app_name]['secret_keys'][key_name]
    fernet = Fernet(key)
    data = data.encode('utf-8')
    decrypted_data =fernet.decrypt(data)
    return jsonify({'status': 'success', 'data': decrypted_data.decode('utf-8')})



@app.route('/onboardApp', methods=['POST'])
@admin_auth
def onboard_app():
    """
    Instantiates a new app in app_db with new api_key and api_token.
    Admin state is set to False.

    @param app-name: name of app to be created
    """
    app_name = request.values.get('app-name')
    if app_name is None:
        return jsonify({'status': 'failed', 'message': 'App name required'}), 400
    if app_name in app_db:
        return jsonify({'status': 'failed', 'message': 'App name already exists'}), 400
    app_db[app_name] = {
        'api_key': app_name,
        'api_token': app_name,
        'is_admin': False,
        'secret_keys': {}
    }
    return jsonify({'status': 'success'})

@app.route('/createSecretKey', methods=['POST'])
@normal_auth
@validate_app_matches_key
def create_secret_key():
    """
    Creates a new secret key for an app.

    @param app-name: name of existing app
    @param secret-key-name: name of secret key to be created
    """
    app_name = request.values.get('app-name')
    if app_name is None:
        return jsonify({'status': 'failed', 'message': 'App name required'}), 400
    if app_name not in app_db:
        return jsonify({'status': 'failed', 'message': 'App does not exist'}), 400
    key_name = request.values.get('secret-key-name')
    if key_name is None:
        return jsonify({'status': 'failed', 'message': 'Secret key name required'}), 400
    if key_name in app_db[app_name]['secret_keys']:
        return jsonify({'status': 'failed', 'message': 'Secret key name already exists'}), 400
    
    app_db[app_name]['secret_keys'][key_name] = Fernet.generate_key().decode('utf-8')
    return jsonify({'status': 'success'})

    



@app.route('/test', methods=['GET','POST'])
def test():
    """
    Prints out DB for testing purposes
    """
    return jsonify(app_db)

if __name__ == '__main__':
    app.run(debug=True)