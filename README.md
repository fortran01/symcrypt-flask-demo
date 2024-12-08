# Symmetric Encryption Demo

This Flask application demonstrates hierarchical key management and symmetric encryption using:

- Master Keys
- Key Encryption Keys (KEKs)
- Data Encryption Keys (DEKs)

## Key Concepts

1. **Master Key**: The root key used to derive KEKs
2. **Key Encryption Keys (KEKs)**: Derived from the master key, used to encrypt DEKs
3. **Data Encryption Keys (DEKs)**: Used for actual data encryption, protected by KEKs

## Features

- Session data encryption using DEKs
- KEK rotation capability
- Secure key derivation using PBKDF2
- Fernet symmetric encryption (AES-128 in CBC mode with PKCS7 padding)

## Implementations

### Local Implementation (app.py)

- Uses local master key for key derivation
- Implements in-memory KEK and DEK management
- Suitable for demonstration and learning purposes

### AWS Implementation (app_aws.py)

- Integrates with AWS KMS for key management
- Uses AWS KMS for master key storage and data key generation
- Provides enhanced security through cloud-based key management
- Requires AWS credentials and KMS key setup

## Setup

### Local Version

- Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

- Install dependencies:

```bash
pip install -r requirements.txt
```

- Run the application:

```bash
python app.py
```

1. Visit http://localhost:5000 in your browser

### AWS Version

1. Set up AWS credentials:
   - Configure AWS credentials in `~/.aws/credentials` or use environment variables
   - Set the `AWS_KMS_KEY_ID` environment variable with your KMS key ARN

2. Run the AWS version:

```bash
python app_aws.py
```

## Security Notes

This is a demonstration application. In a production environment:

- Master keys should be stored in a secure key management system
- KEKs should be stored securely and backed up
- Implement proper key rotation policies
- Add authentication and authorization
- Use HTTPS for all communications
