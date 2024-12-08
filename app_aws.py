from flask import Flask, render_template, request, session, jsonify
import boto3
from botocore.exceptions import ClientError
from base64 import b64encode, b64decode
import os
from datetime import datetime
import json
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(32)

# AWS KMS Key Manager
class AWSKeyManager:
    def __init__(self):
        self.kms_client = boto3.client('kms')
        self.master_key_id = os.getenv('AWS_KMS_KEY_ID')
        logger.info(f"Initialized AWSKeyManager with master key ID: {self.master_key_id}")
        
    def create_data_key(self):
        """Generate a new data key using AWS KMS"""
        try:
            logger.debug("Attempting to generate new data key from AWS KMS")
            response = self.kms_client.generate_data_key(
                KeyId=self.master_key_id,
                KeySpec='AES_256'
            )
            logger.debug("Successfully generated data key")
            # Extract the key ID from the ARN in the response
            key_id = response['KeyId'].split('/')[-1][:8]
            return {
                'encrypted': response['CiphertextBlob'],
                'plaintext': response['Plaintext'],
                'key_id': key_id
            }
        except ClientError as e:
            logger.error(f"AWS KMS error in create_data_key: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in create_data_key: {str(e)}")
            raise
    
    def decrypt_data_key(self, encrypted_data_key):
        """Decrypt an encrypted data key using AWS KMS"""
        try:
            logger.debug("Attempting to decrypt data key using AWS KMS")
            response = self.kms_client.decrypt(
                KeyId=self.master_key_id,
                CiphertextBlob=encrypted_data_key
            )
            logger.debug("Successfully decrypted data key")
            return response['Plaintext']
        except ClientError as e:
            logger.error(f"AWS KMS error in decrypt_data_key: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in decrypt_data_key: {str(e)}")
            raise

    def encrypt_data(self, data):
        """Encrypt data using a new data key"""
        try:
            logger.debug(f"Starting encryption process for data")
            # Generate a new data key
            data_key = self.create_data_key()
            logger.debug("Successfully created new data key")
            
            # Use the plaintext data key to encrypt the data
            from cryptography.fernet import Fernet
            f = Fernet(b64encode(data_key['plaintext']))
            encrypted_data = f.encrypt(data.encode())
            logger.debug("Successfully encrypted data with data key")
            
            return {
                'encrypted_data': encrypted_data,
                'encrypted_data_key': data_key['encrypted'],
                'key_id': data_key['key_id']
            }
        except Exception as e:
            logger.error(f"Error in encrypt_data: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data, encrypted_data_key):
        """Decrypt data using the decrypted data key"""
        try:
            logger.debug("Starting decryption process")
            # First decrypt the data key
            plaintext_key = self.decrypt_data_key(encrypted_data_key)
            logger.debug("Successfully decrypted data key")
            
            # Use the plaintext key to decrypt the data
            from cryptography.fernet import Fernet
            f = Fernet(b64encode(plaintext_key))
            decrypted_data = f.decrypt(encrypted_data).decode()
            logger.debug("Successfully decrypted data")
            
            return decrypted_data
        except Exception as e:
            logger.error(f"Error in decrypt_data: {str(e)}")
            raise

# Initialize AWS key manager
key_manager = AWSKeyManager()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create_session', methods=['POST'])
def create_session():
    try:
        logger.debug("Received create_session request")
        data = request.json
        logger.debug(f"Request data: {data}")
        user_data = data.get('user_data', '')
        
        # Encrypt the user data with a new data key
        logger.debug("Attempting to encrypt user data")
        encryption_result = key_manager.encrypt_data(user_data)
        logger.debug("Successfully encrypted user data")
        
        # Store in session
        session['encrypted_data'] = b64encode(encryption_result['encrypted_data']).decode()
        session['encrypted_data_key'] = b64encode(encryption_result['encrypted_data_key']).decode()
        session['kek_id'] = encryption_result['key_id']
        logger.debug("Stored encrypted data and key in session")
        
        response_data = {
            'status': 'success',
            'message': 'Session created successfully',
            'kek_id': encryption_result['key_id']
        }
        logger.info("Successfully created session")
        return jsonify(response_data)
    except Exception as e:
        error_msg = f"Error in create_session: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'status': 'error',
            'message': error_msg
        }), 500

@app.route('/get_session')
def get_session():
    logger.debug("Received get_session request")
    if 'encrypted_data' not in session or 'encrypted_data_key' not in session:
        logger.warning("No session found")
        return jsonify({'error': 'No session found'})
    
    try:
        # Retrieve and decode the encrypted data and key
        logger.debug("Retrieving session data")
        encrypted_data = b64decode(session['encrypted_data'].encode())
        encrypted_data_key = b64decode(session['encrypted_data_key'].encode())
        
        # Decrypt the data
        logger.debug("Attempting to decrypt session data")
        decrypted_data = key_manager.decrypt_data(encrypted_data, encrypted_data_key)
        logger.debug(f"Successfully decrypted session data: {decrypted_data}")
        
        return jsonify({
            'decrypted_data': decrypted_data
        })
    except Exception as e:
        error_msg = f"Error in get_session: {str(e)}"
        logger.error(error_msg)
        return jsonify({'error': error_msg})

@app.route('/rotate_kek', methods=['POST'])
def rotate_kek():
    logger.debug("Received rotate_kek request")
    try:
        if 'encrypted_data' not in session or 'encrypted_data_key' not in session:
            return jsonify({'error': 'No session found'})

        # Get the current key ID
        old_kek_id = session.get('kek_id')
        
        # Get the current encrypted data
        encrypted_data = b64decode(session['encrypted_data'].encode())
        encrypted_data_key = b64decode(session['encrypted_data_key'].encode())

        # Decrypt the current data
        logger.debug("Decrypting current session data")
        decrypted_data = key_manager.decrypt_data(encrypted_data, encrypted_data_key)

        # Re-encrypt with a new data key
        logger.debug("Re-encrypting with new data key")
        encryption_result = key_manager.encrypt_data(decrypted_data)
        new_kek_id = encryption_result['key_id']

        # Update session with new encrypted data and key
        session['encrypted_data'] = b64encode(encryption_result['encrypted_data']).decode()
        session['encrypted_data_key'] = b64encode(encryption_result['encrypted_data_key']).decode()
        session['kek_id'] = new_kek_id
        
        logger.info("Successfully rotated data key")
        return jsonify({
            'message': 'KEK rotated successfully',
            'old_kek_id': old_kek_id,
            'new_kek_id': new_kek_id
        })

    except Exception as e:
        error_msg = f"Error during key rotation: {str(e)}"
        logger.error(error_msg)
        return jsonify({'error': error_msg})

if __name__ == '__main__':
    app.run(debug=True)
