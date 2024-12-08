from flask import Flask, render_template, request, session, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import os
import json
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Key management
class KeyManager:
    def __init__(self):
        # Master key - in production this would be stored securely
        self.master_key = os.urandom(32)
        # KEKs dictionary - in production these would be stored securely
        self.keks = {}
        # DEKs dictionary - encrypted DEKs stored here
        self.encrypted_deks = {}
        
    def derive_kek(self, kek_id, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        kek = kdf.derive(self.master_key + str(kek_id).encode())
        self.keks[kek_id] = {'key': kek, 'salt': salt}
        return kek, salt
    
    def generate_dek(self, kek_id):
        if kek_id not in self.keks:
            self.derive_kek(kek_id)
        
        # Generate new DEK
        dek = Fernet.generate_key()
        
        # Encrypt DEK with KEK
        f = Fernet(b64encode(self.keks[kek_id]['key']))
        encrypted_dek = f.encrypt(dek)
        
        self.encrypted_deks[kek_id] = encrypted_dek
        return dek
    
    def get_dek(self, kek_id):
        if kek_id not in self.encrypted_deks:
            return self.generate_dek(kek_id)
        
        # Decrypt DEK using KEK
        f = Fernet(b64encode(self.keks[kek_id]['key']))
        return f.decrypt(self.encrypted_deks[kek_id])

# Initialize key manager
key_manager = KeyManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_session', methods=['POST'])
def create_session():
    data = request.json
    user_data = data.get('user_data', '')
    
    # Generate a new KEK ID (in this demo, we'll use timestamp)
    kek_id = int(datetime.now().timestamp())
    
    # Get a DEK for this session
    dek = key_manager.get_dek(kek_id)
    
    # Encrypt the user data
    f = Fernet(dek)
    encrypted_data = f.encrypt(user_data.encode())
    
    # Store in session
    session['kek_id'] = kek_id
    session['encrypted_data'] = encrypted_data.decode()
    
    return jsonify({
        'message': 'Session created',
        'kek_id': kek_id
    })

@app.route('/get_session')
def get_session():
    if 'kek_id' not in session:
        return jsonify({'error': 'No session found'})
    
    kek_id = session['kek_id']
    encrypted_data = session['encrypted_data'].encode()
    
    # Get DEK and decrypt
    dek = key_manager.get_dek(kek_id)
    f = Fernet(dek)
    decrypted_data = f.decrypt(encrypted_data).decode()
    
    return jsonify({
        'decrypted_data': decrypted_data,
        'kek_id': kek_id
    })

@app.route('/rotate_kek', methods=['POST'])
def rotate_kek():
    if 'kek_id' not in session:
        return jsonify({'error': 'No session found'})
    
    old_kek_id = session['kek_id']
    encrypted_data = session['encrypted_data'].encode()
    
    # Decrypt data with old DEK
    old_dek = key_manager.get_dek(old_kek_id)
    f_old = Fernet(old_dek)
    decrypted_data = f_old.decrypt(encrypted_data)
    
    # Generate new KEK and DEK
    new_kek_id = int(datetime.now().timestamp())
    new_dek = key_manager.get_dek(new_kek_id)
    
    # Encrypt with new DEK
    f_new = Fernet(new_dek)
    new_encrypted_data = f_new.encrypt(decrypted_data)
    
    # Update session
    session['kek_id'] = new_kek_id
    session['encrypted_data'] = new_encrypted_data.decode()
    
    return jsonify({
        'message': 'KEK rotated successfully',
        'old_kek_id': old_kek_id,
        'new_kek_id': new_kek_id
    })

if __name__ == '__main__':
    app.run(debug=True)
