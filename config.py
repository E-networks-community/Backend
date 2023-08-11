import hashlib
import hmac
import os
import redis
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session


class ApplicationConfig:

    redis_client = redis.Redis()

    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_TRACK_MODIFICATIONS = os.environ.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS")
    SQLALCHEMY_ECHO = os.environ.get("SQLALCHEMY_ECHO")
    # SQLALCHEMY_DATABASE_URI = r"sqlite:///./db.sqlite"
    username = os.environ.get("USERNAME")
    password = os.environ.get("PASSWORD")
    localhost = os.environ.get("LOCALHOST")
    dbname = os.environ.get("DBNAME")

    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:oXMY8Lu55hbeyGFDYI2w@containers-us-west-168.railway.app:6965/railway"

    DATABASE_ENGINE = create_engine(SQLALCHEMY_DATABASE_URI)
    SESSION_TYPE = os.environ.get("SESSION_TYPE")
    RED = os.environ.get("REDIS_URL")
    REDIS_URL = f"redis://{RED}"
    # SESSION_REDIS = redis.from_url(REDIS_URL)
    SESSION_KEY_PREFIX = os.environ.get("SESSION_KEY_PREFIX")
    SESSION_REDIS = redis_client
    SESSION_PERMANENT = os.environ.get("SESSION_PERMANENT")
    SESSION_USE_SIGNER = os.environ.get("SESSION_USE_SIGNER")

    # MAIL_SERVER = 'smtp25.elasticemail.com'
    # MAIL_SERVER = os.environ.get("MAIL_SERVER")
    # MAIL_PORT = os.environ.get("MAIL_PORT")
    # MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    # MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    # MAIL_USE_TLS = True

    # MAIL_SERVER = 'smtp.elasticemail.com'
    # MAIL_PORT = 2525
    # MAIL_USERNAME = 'info@enetworksagencybanking.com.ng'
    # MAIL_PASSWORD = "6F932A5E77E202CC1B6A70CA0F091C64686C"
    # MAIL_USE_TLS = True

    MAIL_SERVER = 'smtp.elasticemail.com'
    MAIL_PORT = 2525
    MAIL_USERNAME = 'support@enetworksagencybanking.com.ng'
    MAIL_PASSWORD = "A2CDE2AB8EEE085BBF14DFF4D75315C7BF75"
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
