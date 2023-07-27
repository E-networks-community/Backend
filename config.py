import hashlib
import hmac
import os
import redis


class ApplicationConfig:

    redis_client = redis.Redis()

    SECRET_KEY = "my_secret_key_123"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"

    # Update Gmail settings for sending emails
    # Use port 587 for TLS (587 is the standard port for STARTTLS)
    # MAIL_SERVER = 'smtp.googlemail.com'
    # MAIL_PORT = 587
    # MAIL_USERNAME = 'coldnightdev@gmail.com'
    # MAIL_PASSWORD = "yhtjrvgxfycsncbb"
    # MAIL_USE_TLS = True

    SESSION_TYPE = 'redis'
    SESSION_REDIS = redis_client
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = False

    JWT_ACCESS_TOKEN_EXPIRES = 3600


def generate_verification_token(user_id, txn_ref):
    secret_key = ApplicationConfig.SECRET_KEY
    if secret_key:
        data_to_hash = f"{user_id}{txn_ref}"
        return hmac.new(secret_key.encode(), data_to_hash.encode(), hashlib.sha256).hexdigest()
    else:
        raise ValueError("SECRET_KEY is not set in the environment")


def verify_verification_token(user_id, transaction_reference, verification_token):
    try:
        expected_token = generate_verification_token(
            user_id, transaction_reference)
        return verification_token == expected_token
    except Exception as e:
        print("Verification token validation failed:", str(e))
        return False
