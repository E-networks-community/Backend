import hashlib
import hmac
import os
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session


class ApplicationConfig:

    redis_client = redis.Redis()

    SECRET_KEY = "my_secret_key_123"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    # SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:oXMY8Lu55hbeyGFDYI2w@containers-us-west-168.railway.app:6965/railway"

    DATABASE_ENGINE = create_engine(SQLALCHEMY_DATABASE_URI)
    SESSION_TYPE = 'redis'
    REDIS_URL = "redis://red-cj1163k07spjv9picbh0:6379"
    SESSION_REDIS = redis.from_url(REDIS_URL)
    # SESSION_KEY_PREFIX = "your_prefix_here"
    # SESSION_REDIS = redis_client
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = False

    # MAIL_SERVER = 'smtp25.elasticemail.com'
    MAIL_SERVER = 'smtp.elasticemail.com'
    MAIL_PORT = 2525
    MAIL_USERNAME = 'enetworksagencybanking@gmail.com'
    MAIL_PASSWORD = "E9A54FA20AD4D93955A76BEDD66A483174DD"
    MAIL_USE_TLS = True
    DATABASE_INITIALIZED = False

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
