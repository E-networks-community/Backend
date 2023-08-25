from sqlalchemy.exc import SQLAlchemyError
from functools import wraps
import json
import uuid
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, session
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from models import SuccessfulPayment, OTP
from config import ApplicationConfig
from models import Role, db, User, create_roles
import os
import requests
import string
import random
from flask_mail import Mail, Message
import base64
import cloudinary
import cloudinary.uploader
import cloudinary.api
from passlib.hash import bcrypt_sha256

cloudinary.config(
    cloud_name="dagw7pro6",
    api_key="761564937985964",
    api_secret="4GsZPO7aW5TvNNrkIAD4AgC_TTI"
)

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######### Initializing the app with the necessary packages #########
app = Flask(__name__)
# app_asgi = WsgiToAsgi(app)
app.config.from_object(ApplicationConfig)
CORS(app, allow_headers=True, supports_credentials=True)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
migrate = Migrate(app, db)
server_session = Session(app)
db.init_app(app)
# with app.app_context():
#     db.drop_all()
#     db.create_all()
#     create_roles()
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######## Setting a concurent function to be run per request ########


@app.after_request
def add_cors_headers(response):
    # Replace with your frontend domain
    # frontend_domain = 'http://localhost:3000'
    frontend_domain = 'https://www.enetworksagencybanking.com.ng'
    response.headers['Access-Control-Allow-Origin'] = frontend_domain
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PATCH'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
MARASOFT_API_BASE = "https://api.marasoftpay.live"
# Replace with your actual API key
MARASOFT_API_KEY = os.environ.get("MARASOFT_API_KEY")
####################################################################
####################################################################
####################################################################
######### Function to Handle the save profile Image Upload #########
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'profile_images')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


VALID_STATES = [
    'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa',
    'Benue', 'Borno', 'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti',
    'Enugu', 'FCT',  # Added FCT here
    'Gombe', 'Imo', 'Jigawa', 'Kaduna', 'Kano', 'Katsina',
    'Kebbi', 'Kogi', 'Kwara', 'Lagos', 'Nasarawa', 'Niger', 'Ogun',
    'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers', 'Sokoto', 'Taraba',
    'Yobe', 'Zamfara'
]

####################################################################
####################################################################
####################################################################
####################################################################
################## Function to save profile Image ##################


def upload_image_to_cloudinary(image):
    # Upload the image to Cloudinary
    result = cloudinary.uploader.upload(
        image,
        quality='auto:low',  # Set compression quality
    )
    #

    # Get the public URL of the uploaded image from the Cloudinary response
    image_url = result['url']

    return image_url

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


def require_role(role_names):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.filter_by(id=user_id).first()
            if not user or user.role.role_name not in role_names:
                return jsonify(message='Insufficient permissions'), 403
            return func(*args, **kwargs)
        return wrapper
    return decorator


def has_role(user_id, roles):
    user = User.query.get(user_id)
    if user and user.role:
        return user.role.role_name in roles
    return False

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
# Function to generate OTP


def generate_otp():
    return ''.join(random.choices('0123456789', k=6))
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
# Function to send OTP to user's email


# @app.route("/send_email/<email>/<otp>", methods=["GET"])
def send_otp_to_email_for_reset(email, otp):
    subject = "E-networksCommunity Reset Password"

    msg_body = f"Dear user,\n\n" \
               f"Verify your Email: {email}\n" \
               f"Your OTP for password reset is: {otp}\n\n" \
               f"Please use this OTP to reset your password. If you didn't create this Request, " \
               f"you can ignore this email.\n\n" \
               f"Thank you!"

    try:
        result = send_email_with_otp(
            email, subject, 'verify_email', otp=otp, msg_body=msg_body)
        if result:
            return "Email sent.....", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500

# @app.route("/send_email/<email>/<otp>", methods=["GET"])


def send_reciept_to_user(email, user_name):
    subject = "E-networks Digital Card Receipt"

    try:
        result = send_email_with_no_otp(
            email, subject, 'reciept', user_name=user_name)
        if result:
            return "Email sent successfully", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500
####################################################################
####################################################################
####################################################################


def send_email_with_otp(to, subject, template, otp, **kwargs):
    msg = Message(subject, recipients=[to], sender=app.config['MAIL_USERNAME'])
    msg.body = "Hello"
    msg.html = render_template(
        template + '.html', user_email=to, otp=otp, **kwargs)

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(e)
        return False


def send_email_with_no_otp(to, subject, template, user_name, **kwargs):
    msg = Message(subject, recipients=[to], sender=app.config['MAIL_USERNAME'])
    msg.html = render_template(
        template + '.html', user_name=user_name, **kwargs)

    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(e)
        return False

####################################################################
####################################################################
####################################################################
# Function to send OTP to user's email


def send_otp_to_email_for_verify(email, otp):
    subject = "E-networksCommunity Verify Email"

    try:
        result = send_email_with_otp(email, subject, 'verify_email', otp=otp)
        if result:
            return "Email sent successfully", 200
        else:
            return jsonify(message='Failed to send email'), 500
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while sending the email'), 500

####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


@app.route('/')
def hello_world():
    return 'Hello from Koyeb'
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


def generate_referral_code():
    # Generate a random string of 6 characters (upper case letters and digits)
    letters_and_digits = string.ascii_uppercase + string.digits
    while True:
        referral_code = ''.join(random.choices(letters_and_digits, k=6))
        # Check if the referral code already exists in the database
        existing_user = User.query.filter_by(
            referral_code=referral_code).first()
        if not existing_user:
            break
    return referral_code
####################################################################
####################################################################
####################################################################
####################################################################
############################## Routes ##############################
####################################################################


@app.route("/profile_images/<filename>", methods=["GET"])
def serve_profile_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################


@app.route('/agent/register', methods=['POST'])
def register_agent():
    return register_user(role_name='Agent')


@app.route('/intern/register', methods=['POST'])
def register_intern():
    return register_user(role_name='Intern')


@app.route('/mobilizer/register', methods=['POST'])
def register_mobilizer():
    return register_user(role_name='Mobilizer')

####################################################################
####################################################################
####################################################################
####################################################################
# Add referral_link as a parameter with a default value of None


def register_user(role_name, referrer_id=None):
    # Use request.form.to_dict() to get the form data (excluding files)
    data = request.form.to_dict()
    profile_image = request.files.get('profile_image')

    if not data:
        return jsonify(message='No data provided in the request'), 400

    if not profile_image:
        return jsonify(message='Profile image is required'), 400

    # Extract user registration data from the JSON request
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    referral_code = data.get('referral_code')

    # New fields
    state = data.get('state')
    local_government_area = data.get('local_government_area')
    address = data.get('address')
    account = data.get('account')
    bankName = data.get('bankName')
    enairaId = data.get('enaira_Id', None)

    if not all([first_name, last_name, email, password, phone_number, state, local_government_area, address, account, bankName]):
        return jsonify(message='Missing required fields in the request'), 400

    # Check if the email is already in use
    if User.query.filter_by(email=email).first():
        return jsonify(message='Email already registered'), 409

    # Validate state
    if state not in VALID_STATES:
        return jsonify(message='Invalid state provided'), 400

    # Check if the referral code exists and get the referrer user
    referrer = None
    if referral_code:
        referrer = User.query.filter_by(referral_code=referral_code).first()
        if not referrer:
            return jsonify(message='Invalid referral code provided'), 400

    # Get the appropriate role based on the role_name provided
    role = Role.query.filter_by(role_name=role_name).first()
    if not role:
        return jsonify(message=f'Invalid role_name provided: {role_name}'), 400

    # Generate a unique referral code for the new user
    hashed_password = bcrypt_sha256.hash(password)

    new_user_referral_code = generate_referral_code()

    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        phone_number=phone_number,
        referral_code=new_user_referral_code,
        role=role,
        referred_by_id=referrer_id,
        state=state,
        local_government=local_government_area,
        address=address,
        enairaId=enairaId,
        account=account,
        bank_name=bankName
    )

    try:
        if profile_image and allowed_file(profile_image.filename):
            # Upload the profile image to Cloudinary
            profile_image_url = upload_image_to_cloudinary(profile_image)
            new_user.profile_image = profile_image_url

        # Save the referral link before committing the user object
        new_user.referral_link = new_user.generate_referral_link()

        # Commit the user object with the referral link and profile image (if any)
        db.session.add(new_user)
        db.session.commit()

        email_verification_otp = generate_otp()

        otp = OTP(user_id=new_user.id, email=new_user.email,
                  otp=email_verification_otp)
        db.session.add(otp)
        db.session.commit()

        # Send the OTP to the user's email for verification
        send_otp_to_email_for_verify(new_user.email, email_verification_otp)

        # Save the OTP in the user's session for verification later
        identity = {"user_id": str(
            new_user.id), "email_verification_otp": email_verification_otp}
        access_token = create_access_token(identity=json.dumps(identity))

        return jsonify({"access_token": access_token, "role": new_user.role.role_name, "otp": email_verification_otp}), 200
    except Exception as e:
        db.session.rollback()
        print("Error during user registration:", str(e))
        return jsonify(message='Failed to register user. Please try again later.'), 500


@app.route('/login', methods=["POST"])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None or not bcrypt_sha256.verify(password, user.password):
        return jsonify({"error": "Unauthorized"}), 401

    # Create the access token with the user ID as the identity
    access_token = create_access_token(identity=str(user.id))

    # Return the access token and user role as JSON response
    return jsonify({"access_token": access_token, "role": user.role.role_name}), 200


@app.route('/verify-email', methods=['POST'])
@jwt_required()
def verify_email():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        if not user:
            return jsonify(message='User not found'), 404

        data = request.form
        email_verification_otp = data.get('otp')
        email = user.email

        if not email_verification_otp or not email:
            return jsonify(message='OTP and email fields are required'), 400

        # Get the OTP from the OTP table based on the user's email
        otp_entry = OTP.query.filter_by(user_id=user_id, email=email).first()

        if not otp_entry:
            return jsonify(message='OTP entry not found'), 404

        stored_otp = otp_entry.otp

        if stored_otp != email_verification_otp:
            return jsonify(message='Invalid OTP'), 401

        if user.is_email_verified:
            return jsonify(message="You have already verified your email"), 200

        # Mark the user's email as verified
        user.is_email_verified = True
        db.session.commit()

        # Remove the OTP entry from the OTP table after successful verification
        db.session.delete(otp_entry)
        db.session.commit()

        return jsonify(message='Email verified successfully'), 200

    except KeyError:
        return jsonify(message='Invalid JWT token'), 401
    except Exception as e:
        db.session.rollback()
        print("Error during email verification:", str(e))
        return jsonify(message='Failed to verify email. Please try again later.'), 500


@app.route("/referral/<referral_code>", methods=["POST"])
def register_user_with_referral(referral_code):
    try:
        # Retrieve the user data from the request form
        data = request.form.to_dict()
        profile_image = request.files.get('profile_image')

        if not data:
            return jsonify(message='No data provided in the request'), 400

        if not profile_image:
            return jsonify(message='Profile image is required'), 400

        # Extract user registration data from the JSON request
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        email = data.get('email')
        password = data.get('password')
        phone_number = data.get('phone_number')

        # New fields
        state = data.get('state')
        local_government_area = data.get('local_government_area')
        address = data.get('address')
        account = data.get('account')
        bankName = data.get('bankName')
        enairaId = data.get('enaira_Id', None)

        if not all([first_name, last_name, email, password, phone_number, state, local_government_area, address, account, bankName]):
            return jsonify(message='Missing required fields in the request'), 400

        # Check if the email is already in use
        if User.query.filter_by(email=email).first():
            return jsonify(message='Email already registered'), 409

        # Validate state
        if state not in VALID_STATES:
            return jsonify(message='Invalid state provided'), 400

        # Check if the referral code exists and get the referrer user
        referrer = User.query.filter_by(referral_code=referral_code).first()
        if not referrer:
            return jsonify(message='Invalid referral code provided'), 400

        # Get the appropriate role (e.g., "Intern") based on the role_name
        role_name = "Intern"  # Change this to the desired role name
        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            return jsonify(message=f'Invalid role_name provided: {role_name}'), 400

        # Generate a unique referral code for the new user
        hashed_password = bcrypt_sha256.hash(password)
        new_user_referral_code = generate_referral_code()

        # Create the new user with referral information
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password,
            phone_number=phone_number,
            referral_code=new_user_referral_code,
            role=role,
            referred_by_id=referrer.id,  # Set the referrer ID
            state=state,
            local_government=local_government_area,
            address=address,
            enairaId=enairaId,
            account=account,
            bank_name=bankName
        )

        if profile_image and allowed_file(profile_image.filename):
            # Upload the profile image to Cloudinary
            profile_image_url = upload_image_to_cloudinary(profile_image)
            new_user.profile_image = profile_image_url

        # Save the referral link before committing the user object
        new_user.referral_link = new_user.generate_referral_link()

        # Commit the user object with the referral link and profile image (if any)
        db.session.add(new_user)
        db.session.commit()
        db.session.commit()

        email_verification_otp = generate_otp()

        otp = OTP(user_id=new_user.id, email=new_user.email,
                  otp=email_verification_otp)
        db.session.add(otp)
        db.session.commit()

        # Send the OTP to the user's email for verification
        send_otp_to_email_for_verify(new_user.email, email_verification_otp)

        # Save the OTP in the user's session for verification later
        identity = {"user_id": str(
            new_user.id), "email_verification_otp": email_verification_otp}
        access_token = create_access_token(identity=json.dumps(identity))

        return jsonify({"access_token": access_token, "role": new_user.role.role_name, "otp": email_verification_otp}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        print("Error during user registration:", str(e))
        return jsonify(message='Failed to register user. Please try again later.'), 500


@app.route('/edit-user', methods=['PATCH'])
@jwt_required()
def edit_user():
    try:
        current_user_id = get_jwt_identity()

        user = User.query.get(current_user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404

        # Get the data from the PATCH request
        data = request.form.to_dict()

        # Check if the current user has permission to edit this user (optional, if needed)
        # For example, you can check if the current user is the same as the user being edited.

        # Update user attributes based on provided data
        if 'password' in data:
            new_password = data.get("password")
            hashed_password = bcrypt_sha256.hash(new_password)
            user.password = hashed_password

        if 'address' in data:
            address = data.get("address")
            user.address = address

        # Commit the changes to the database
        db.session.commit()

        return jsonify({"message": f"User {current_user_id} data updated successfully"}), 200

    except Exception as e:
        return jsonify({"message": "An error occurred", "error": str(e)}), 500


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()

    print(f"This is the user ID: {user_id}")

    # Query the database to fetch the user's data
    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify(message='User not found'), 404

    # Convert the user data to a dictionary using the to_dict() method from the User model
    user_data = user.to_dict()

    # Get the list of referred users and their email verification status
    referral_list = user.get_referral_list()
    # Add the referral list to the user data dictionary
    user_data['referral_list'] = referral_list
    # referral_history = user.get_referral_history()
    # user_data['recent_referral_history'] = referral_history

    # Return the user's data as a JSON response
    return jsonify(user_data), 200


@app.route('/resend-otp', methods=['POST'])
@jwt_required()  # Assuming you are using JWT for authentication
def resend_otp():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify(message='User not found'), 404

    # Generate a new OTP and update it in the database
    new_otp = generate_otp()
    otp_record = OTP.query.filter_by(user_id=user_id).first()
    if otp_record:
        otp_record.otp = new_otp
        # otp_record.timestamp = datetime.utcnow()  # Update the timestamp
    else:
        otp_record = OTP(user_id=user_id, email=user.email, otp=new_otp)
        db.session.add(otp_record)

    try:
        db.session.commit()

        # Send the new OTP to the user's email for verification
        send_otp_to_email_for_verify(user.email, new_otp)

        return jsonify(message=f'New OTP has been sent to your email {new_otp}'), 200
    except Exception as e:
        db.session.rollback()
        print("Error during OTP resend:", str(e))
        return jsonify(message='Failed to resend OTP. Please try again later.'), 500


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify(message='Email field is required'), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify(message='User not found'), 404

    # Generate OTP and send it to the user's email
    otp = generate_otp()
    send_otp_to_email_for_reset(email, otp)

    # Store the OTP in the user's session for verification later
    session['otp'] = otp
    session['user_id'] = user.id

    return jsonify(message='OTP sent to email'), 200


@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    otp = data.get('otp')
    new_password = data.get('new_password')

    # Get the OTP and user ID from the session
    stored_otp = session.get('otp')
    user_id = session.get('user_id')

    if not otp or not new_password:
        return jsonify(message='OTP and new_password fields are required'), 400

    if stored_otp != otp:
        return jsonify(message='Invalid OTP'), 401

    user = User.query.get(user_id)
    if not user:
        return jsonify(message='User not found'), 404

    # Update the user's password
    hashed_new_password = bcrypt.generate_password_hash(new_password)
    user.password = hashed_new_password
    db.session.commit()

    # Clear the OTP and user ID from the session
    session.pop('otp', None)
    session.pop('user_id', None)

    return jsonify(message='Password updated successfully'), 200


@app.route('/users', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_all_users():
    try:
        users = User.query.all()
        user_data = []

        for user in users:
            if user.role:  # Check if user.role is not None
                user_item = {
                    'id': user.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'has_paid': user.has_paid,
                    'Reffered_me': user.referred_by_id,
                    'role': user.role.role_name,  # Access role_name only if user.role is not None
                }
            else:
                # Handle the case where user.role is None (e.g., set a default role name)
                user_item = {
                    'id': user.id,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'role': 'Default Role',  # Set a default role name
                }

            user_data.append(user_item)

        return jsonify(user_data), 200
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while fetching users'), 500


@app.route('/users/<user_id>', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_user_by_id(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    user_data = user.to_dict()  # Convert User object to a dictionary

    return jsonify(user_data)


@app.route('/users/<user_id>/referrals', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_user_referrals(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404

    referral_list = user.get_referral_list()

    return jsonify(referral_list)


@app.route('/get/<referral_code>', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def check_ref_code(referral_code):
    referrer = User.query.filter_by(referral_code=referral_code).first()
    if not referrer:
        return jsonify(message='Invalid referral code provided'), 400

    return jsonify(message="Found"), 200


@app.route("/pay/", methods=["POST"])
@jwt_required()
def initialize_payment():
    # Retrieve the user from the database

    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    # Check if the user exists
    if not user:
        return jsonify({"error": "User not found"}), 404

    try:
        # Generate a unique transaction reference (merchant_tx_ref)
        transaction_reference = user.id

        # verification_token = generate_verification_token(
        #     user_id, transaction_reference)

        # Prepare the data payload
        payload = {
            "data": {
                "public_key": "MSFT_live_475HC3DIJWVV7YBMJ5X6MEXT4FUU23L",
                "request_type": "live",
                "merchant_tx_ref": transaction_reference,
                # "redirect_url": f"https://enetworks-tovimikailu.koyeb.app/pay/{user_id}/verify",
                "redirect_url": f"https://www.enetworksagencybanking.com.ng/",
                "name": user.first_name,
                "email_address": user.email,
                "phone_number": user.phone_number,
                "amount": 1500,
                "currency": "NGN",
                "user_bear_charge": "yes",
                "preferred_payment_option": "card",
                "description": "payment"
            }
        }

        # Make a payment request to Marasoft API to initiate payment
        response = requests.post(
            "https://checkout.marasoftpay.live/initiate_transaction",
            json=payload,
            headers={
                "Content-Type": "application/json",
            }
        )

        data = response.json()

        if response.status_code == 200 and data.get("status") == "success":
            # Update this line to access the payment URL
            payment_url = data["url"]
            redirect_url = f"https://enetworks-tovimikailu.koyeb.app/pay/{user_id}/verify"
            user.payment_reference = redirect_url
            db.session.commit()

            return jsonify({"payment_url": payment_url, "redirect_url": redirect_url})
        else:
            error_message = data.get("error") if data.get(
                "error") else "Payment initiation failed"
            print("Payment initiation failed:", error_message)
            return jsonify({"error": error_message}), 500

    except Exception as e:
        print("Payment initiation failed:", str(e))
        return jsonify({"error": "Payment initiation failed"}), 500


@app.route("/pay/<user_id>/verify", methods=["GET"])
def verify_payment(user_id):
    # Retrieve the query parameters from the callback URL
    status = request.args.get("status")
    transaction_reference = request.args.get("txn_ref")
    payment_reference = request.args.get("msft_ref")

    print("Received values:")
    print("Transaction Reference:", transaction_reference)
    print("Payment Reference:", payment_reference)

    # Check if the required parameters are missing
    if not status or not transaction_reference or not payment_reference:
        return jsonify({"error": "Missing required parameters"}), 400

    try:
        # Check if the payment was successful
        if status.lower() == "successful":
            # Retrieve the user from the database based on the user ID
            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "User not found"}), 404

            # Check if the payment has already been processed for this user and transaction reference
            existing_payment = SuccessfulPayment.query.filter_by(
                user_id=user_id,
                transaction_reference=transaction_reference
            ).first()

            if existing_payment:
                # Payment has already been processed, do not update earnings again
                return redirect("https://www.enetworksagencybanking.com.ng/")

            # Save the successful payment record to prevent duplicate earnings updates
            successful_payment = SuccessfulPayment(
                user_id=user_id,
                transaction_reference=transaction_reference,
                payment_amount=1500  # Change this to the actual payment amount
            )
            db.session.add(successful_payment)

            # Check if the user was referred by a mobilizer
            if user.referred_me and user.referred_me.role and user.referred_me.role.role_name == 'Mobilizer':
                referred_by_mobilizer = user.referred_me
                referred_by_mobilizer.earnings += 100  # Update mobilizer's earnings
                db.session.add(referred_by_mobilizer)

            # Check if the user's state has an executive
            if user.state:
                executives = User.query.filter_by(state=user.state).all()
                for executive in executives:
                    if executive.role and executive.role.role_name == 'Executives':
                        executive.earnings += 50
                        db.session.add(executive)

            db.session.commit()

            send_reciept_to_user(user.email, user.first_name)

            # Update the user's payment status if the payment is successful
            user.has_paid = True
            # Set the payment reference as the transaction reference
            user.payment_reference = transaction_reference
            db.session.commit()

            # Redirect to the desired URL or return a response indicating the payment was successful
            return redirect("https://www.enetworksagencybanking.com.ng/")
            # return jsonify(message="Payment Done")

        # Return a response indicating the payment was not successful
        response = {
            "paid": False,
            "user_id": user_id,
        }
        return jsonify(response), 201

    except Exception as e:
        print("Payment verification failed:", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Payment verification failed"}), 500


def get_all_admins():
    # Query the database to get all users with the 'Admin' role
    admins = User.query.join(Role).filter_by(role_name='Admin').all()

    # Convert the list of admins to dictionaries and return as JSON response
    admins_data = [{
        'id': admin.id,
        'first_name': admin.first_name,
        'last_name': admin.last_name,
        'email': admin.email,
        'role': admin.role.role_name,
    } for admin in admins]
    return jsonify(admins_data)


@app.route('/interns', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_all_interns():
    # Query the database to get all users with the 'Intern' role
    interns = User.query.join(Role).filter_by(role_name='Interns').all()

    # Convert the list of interns to dictionaries and return as JSON response
    intern_data = [intern.to_dict() for intern in interns]
    return jsonify(intern_data)


@app.route('/mobilizer', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_all_mobilizer():
    # Query the database to get all users with the 'Intern' role
    mobilizers = User.query.join(Role).filter_by(role_name='Mobilizers').all()

    # Convert the list of interns to dictionaries and return as JSON response
    mobilizer_data = [mobilizer.to_dict() for mobilizer in mobilizers]
    return jsonify(mobilizer_data)


@app.route('/executives', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def get_all_execs():
    # Query the database to get all users with the 'Intern' role
    execs = User.query.join(Role).filter_by(role_name='Executives').all()

    # Convert the list of interns to dictionaries and return as JSON response
    exec_data = [exec.to_dict() for exec in execs]
    return jsonify(exec_data)


@app.route('/upload', methods=['POST'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def upload_image():
    try:
        print("Started uploading")
        image = request.files['image']
        if not image:
            return jsonify({'error': 'No image provided'}), 400

        # Upload the image to Cloudinary and set the compression settings
        result = cloudinary.uploader.upload(
            image,
            quality='auto:low',  # Set compression quality
        )

        return jsonify({'url': result['secure_url']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/logout", methods=["POST"])
def logout():
    # Clear the token on the client-side (e.g., remove from local storage or delete the token cookie)
    # No server-side token handling is required
    return jsonify({"message": "Logged out successfully"}), 200


@app.route('/referral-history', methods=['GET'])
def get_referral_history():
    # Get all users who have referred others
    referrers = User.query.filter(User.referred_users.any()).all()

    referral_history_list = []

    for referrer in referrers:
        # Get the list of users referred by this referrer
        referred_users = referrer.referred_users.all()

        # Iterate through referred users and construct the data for each referral
        for referred_user in referred_users:
            referral_data = {
                'referrer': f"{referrer.first_name} {referrer.last_name}",
                'referred': f"{referred_user.first_name} {referred_user.last_name}",
                'date': referred_user.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
            referral_history_list.append(referral_data)

    return jsonify(referral_history_list), 200


def generate_enaira_id():
    unique_id = uuid.uuid4().int & (1 << 64) - 1  # Convert UUID to 64-bit integer
    return unique_id % 10**10  # Keep the last 10 digits


def generate_unique_enaira_id():
    while True:
        enaira_id = generate_enaira_id()
        existing_user = User.query.filter_by(enairaId=str(enaira_id)).first()
        if not existing_user:
            return enaira_id


def generate_account_number():
    while True:
        unique_id = uuid.uuid4().int & (1 << 64) - 1  # Convert UUID to 64-bit integer
        existing_user = User.query.filter_by(account=unique_id).first()
        if not existing_user:
            return unique_id % 10**10  # Keep the last 10 digits


@app.route('/create-executives', methods=['POST'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def create_executives():
    valid_states = [
        'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa',
        'Benue', 'Borno', 'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti',
        'Enugu', 'FCT',  # Added FCT here
        'Gombe', 'Imo', 'Jigawa', 'Kaduna', 'Kano', 'Katsina',
        'Kebbi', 'Kogi', 'Kwara', 'Lagos', 'Nasarawa', 'Niger', 'Ogun',
        'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers', 'Sokoto', 'Taraba',
        'Yobe', 'Zamfara'
    ]

    try:
        for state in valid_states:
            email = f"enetworksEexecutive{state.replace(' ', '').capitalize()}@Enet.com"
            password = email  # Use the email as the password for simplicity
            first_name = "To Be Edited"
            last_name = "To Be Edited"
            phone_number = "To Be Edited"
            address = "To Be Edited"
            bankName = "To be Edited"

            role_name = "Executives"  # Assuming 'Executives' is the role name for executives

            # Check if the executive already exists
            existing_executive = User.query.filter_by(email=email).first()
            if not existing_executive:
                # Create a new executive user
                role = Role.query.filter_by(role_name=role_name).first()
                if role:
                    new_executive = User(
                        first_name=first_name,
                        last_name=last_name,
                        email=email,
                        password=bcrypt_sha256.hash(password),
                        phone_number=phone_number,
                        role=role,
                        state=state,  # Set the state to the current state being iterated
                        address=address,
                        local_government="To Be Edited",
                        is_email_verified=True,  # Mark email as verified for simplicity
                        account=0000,
                        enairaId="0000",
                        bank_name="To be edited"
                    )

                    db.session.add(new_executive)
                    db.session.commit()

        return jsonify(message="Executives created successfully"), 201
    except Exception as e:
        db.session.rollback()
        print("Error creating executives:", str(e))
        return jsonify(message="Failed to create executives"), 500


@app.route('/executive-dashboard', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def executive_dashboard():
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        if current_user.role.role_name != 'Executives':
            return jsonify(message='Access denied'), 403

        state = current_user.state

        # Get total registrations for the state
        total_registrations = User.get_total_users_per_state(state)

        # Get user details for the state (excluding the executive)
        user_details = []
        for user in User.query.filter(User.state == state, User.id != current_user_id).all():
            user_details.append({
                'address': user.address,
                'email': user.email,
                'name': user.first_name + ' ' + user.last_name,
                'phone_number': user.phone_number
            })

        # Get executive's profile details
        profile_details = {
            'name': current_user.first_name + ' ' + current_user.last_name,
            'email': current_user.email,
            'phone_number': current_user.phone_number,
            'state': current_user.state,
            'earnings': current_user.earnings
        }

        # Construct the response JSON
        response = {
            'state': state,
            'total_registrations': total_registrations,
            'profile_details': profile_details,
            'state_registrations': user_details
        }

        return jsonify(response), 200
    except Exception as e:
        print("Error fetching executive dashboard:", str(e))
        return jsonify(message="An error occurred"), 500


@app.route('/admin-dashboard')
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def admin_dashboard():
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)

        # Get total number of registered users
        total_users = User.get_total_registered_users()

        # Get total number of registered executives
        total_executives = User.query.filter_by(role_id=3).count()

        # Get total number of registered interns
        total_interns = User.query.filter_by(role_id=5).count()

        # Get total number of registered mobilizers
        total_mobilizers = User.query.filter_by(role_id=4).count()

        # Get total number of referrals
        total_referrals = SuccessfulPayment.query.count()

        # Get referral data
        referrals = []
        for payment in SuccessfulPayment.query.all():
            referrer = db.session.query(User).filter_by(
                id=payment.user_id).first()
            referred = db.session.query(User).filter_by(
                id=referrer.referred_by_id).first()

            referrer_name = f"{referrer.first_name} {referrer.last_name}"
            referred_name = f"{referred.first_name} {referred.last_name}" if referred else "No Referral"

            referrals.append({
                'referred_name': referred_name,
                'referrer_name': referrer_name
            })

        # Get details for all interns, mobilizers, and executives
        interns_data = get_role_data(5)
        mobilizers_data = get_role_data(4)
        executives_data = get_role_data(3)

        # Construct the response JSON
        response = {
            'name': current_user.first_name + ' ' + current_user.last_name,
            'phone_number': current_user.phone_number,
            'email': current_user.email,
            'role': current_user.role.role_name,
            'total_users': total_users,
            'total_executives': total_executives,
            'total_interns': total_interns,
            'total_mobilizers': total_mobilizers,
            'total_referrals': total_referrals,
            'referrals': referrals,
            'interns_data': interns_data,
            'mobilizers_data': mobilizers_data,
            'executives_data': executives_data,
            'profile_image': current_user.profile_image
        }

        return jsonify(response), 200
    except Exception as e:
        print("Error fetching admin dashboard:", str(e))
        return jsonify(message="An error occurred"), 500


def get_role_data(role_id):
    role_data = []
    for user in User.query.filter_by(role_id=role_id).all():
        role_data.append({
            'name': user.first_name + ' ' + user.last_name,
            'email': user.email,
            'phone_number': user.phone_number,
            'state': user.state,
            'address': user.address,
            'has_paid': user.has_paid
        })
    return role_data


@app.route('/create-admin', methods=['POST'])
@jwt_required()
@require_role(['Admin', 'Super Admin', "Executives"])
def create_admin():
    try:
        email = "Admin@Enet.com"
        password = email  # Use the email as the password for simplicity
        first_name = "To Be Edited"
        last_name = "To Be Edited"
        phone_number = "To Be Edited"
        address = "To Be Edited"

        role_name = "Admin"  # Assuming 'Executives' is the role name for executives

        # Check if the executive already exists
        existing_admin = User.query.filter_by(email=email).first()
        if not existing_admin:
            # Create a new executive user
            role = Role.query.filter_by(role_name=role_name).first()
            if role:
                new_admin = User(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=bcrypt_sha256.hash(password),
                    phone_number=phone_number,
                    role=role,
                    state="Null",  # Set the state to the current state being iterated
                    address=address,
                    local_government="To Be Edited",
                    is_email_verified=True,  # Mark email as verified for simplicity
                    account=generate_account_number(),
                    enairaId="To be Edited",
                    bank_name="To be Added"
                )

                db.session.add(new_admin)
                db.session.commit()

        return jsonify(message="Admin created successfully"), 201
    except Exception as e:
        db.session.rollback()
        print("Error creating Admin:", str(e))
        return jsonify(message="Failed to create Admin"), 500


# @app.route("/webhook/payment", methods=["POST"])
# def handle_payment_webhook():
#     try:
#         data = request.json

#         # Extract relevant fields from the webhook payload
#         status = data.get("status")
#         transaction_reference = data.get("merchant_ref")
#         payment_reference = data.get("msft_ref")
#         # Add more fields as needed

#         if not status or not transaction_reference or not payment_reference:
#             return jsonify({"error": "Missing required parameters"}), 400

#         # Retrieve the user from the database based on the payment_reference
#         user = User.query.filter_by(id=transaction_reference).first()

#         if not user:
#             return jsonify({"error": "User not found"}), 404

#         # Check if the payment has already been processed for this user and transaction reference
#         existing_payment = SuccessfulPayment.query.filter_by(
#             user_id=user.id
#         ).first()

#         if existing_payment:
#             # Payment has already been processed, do not update earnings again
#             return jsonify({"message": "Payment already processed"}), 200

#         # Check if the payment was successful
#         if status.lower() == "success":
#             if not user.has_paid:
#                 # Update user's payment status and perform earnings calculations
#                 user.has_paid = True

#                 if user.referred_me and user.referred_me.role and user.referred_me.role.role_name == "Mobilizer":
#                     referred_by_mobilizer = user.referred_me
#                     referred_by_mobilizer.earnings += 100
#                     db.session.add(referred_by_mobilizer)

#                 if user.state:
#                     executives = User.query.filter_by(state=user.state).all()
#                     for executive in executives:
#                         if executive.role and executive.role.role_name == "Executives":
#                             executive.earnings += 50
#                             db.session.add(executive)

#                 # Create a new entry in the SuccessfulPayment table
#                 successful_payment = SuccessfulPayment(
#                     user_id=user.id,
#                     transaction_reference=transaction_reference,
#                     payment_amount=1500,  # Set the payment amount

#                 )
#                 db.session.add(successful_payment)

#                 db.session.commit()

#                 # Send receipt to user
#                 send_reciept_to_user(user.email, user.first_name)

#             return jsonify({"message": "Payment processed successfully"}), 200
#         else:
#             return jsonify({"message": "Payment not successful"}), 200

#     except Exception as e:
#         print("Error processing payment webhook:", str(e))
#         return jsonify({"error": "An error occurred while processing the webhook"}), 500


@app.route("/webhook/payment", methods=["POST"])
def handle_payment_webhook():
    try:
        data = request.json

        # Extract relevant fields from the webhook payload
        status = data.get("status")
        transaction_reference = data.get("merchant_ref")
        payment_reference = data.get("msft_ref")
        settled_amount = float(data.get("settled_amount"))

        if not status or not transaction_reference or not payment_reference:
            return jsonify({"error": "Missing required parameters"}), 400

        # Retrieve the user from the database based on the payment_reference
        user = User.query.filter_by(id=transaction_reference).first()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Check if the payment has already been processed for this user and transaction reference
        existing_payment = SuccessfulPayment.query.filter_by(
            user_id=user.id
        ).first()

        if existing_payment:
            # Payment has already been processed, do not update earnings again
            return jsonify({"message": "Payment already processed"}), 200

        # Check if the payment was successful and settled amount is sufficient
        if status.lower() == "success":
            if settled_amount < 1500:
                return jsonify({"message": "Payment successful but settled amount is insufficient"}), 200

            if not user.has_paid:
                # Update user's payment status and perform earnings calculations
                user.has_paid = True

                if user.referred_me and user.referred_me.role and user.referred_me.role.role_name == "Mobilizer":
                    referred_by_mobilizer = user.referred_me
                    referred_by_mobilizer.earnings += 100
                    db.session.add(referred_by_mobilizer)

                if user.state:
                    executives = User.query.filter_by(state=user.state).all()
                    for executive in executives:
                        if executive.role and executive.role.role_name == "Executives":
                            executive.earnings += 50
                            db.session.add(executive)

                # Create a new entry in the SuccessfulPayment table
                successful_payment = SuccessfulPayment(
                    user_id=user.id,
                    transaction_reference=transaction_reference,
                    payment_amount=settled_amount,  # Use settled_amount as payment amount
                )
                db.session.add(successful_payment)

                db.session.commit()

                # Send receipt to user
                send_reciept_to_user(user.email, user.first_name)

            return jsonify({"message": "Payment processed successfully"}), 200
        else:
            return jsonify({"message": "Payment not successful"}), 200

    except Exception as e:
        print("Error processing payment webhook:", str(e))
        return jsonify({"error": "An error occurred while processing the webhook"}), 500


# @app.route('/edit/<user_id>', methods=['PUT'])
# @jwt_required()  # This ensures that only authenticated users (with a valid token) can access this route
# @require_role(['Admin', 'Super Admin'])
# def edit_user_with_id(user_id):
#     try:
#         current_user_id = get_jwt_identity()  # Get the ID of the authenticated user
#         if not current_user_id:
#             return jsonify({'message': 'Invalid user'}), 401

#         user = User.query.get(user_id)
#         if not user:
#             return jsonify({'message': 'User not found'}), 404

#         # Update user data based on the request JSON
#         updated_data = request.get_json()
#         if 'first_name' in updated_data:
#             user.first_name = updated_data['first_name']
#         if 'last_name' in updated_data:
#             user.last_name = updated_data['last_name']
#         if 'email' in updated_data:
#             user.email = updated_data['email']
#         # Update other fields as needed
#         if 'has_paid' in updated_data:
#             user.has_paid = updated_data['has_paid']
#         if 'earnings' in updated_data:
#             user.earnings = updated_data['earnings']
#         if 'is_email_verified' in updated_data:
#             user.is_email_verified = updated_data['is_email_verified']
#         if 'referrer' in updated_data:
#             user.referred_by_id = updated_data['referrer']
#         if 'account' in updated_data:
#             user.account = updated_data['account']
#         if 'role_id' in updated_data:
#             user.role_id = updated_data['role_id']
#         if 'password' in updated_data:
#             new_password = updated_data['password']
#             hashed_password = bcrypt_sha256.hash(new_password)
#             user.password = hashed_password

#         db.session.commit()

#         return jsonify({'message': 'User data updated successfully'}), 200

#     except Exception as e:
#         print(e)
#         return jsonify({'message': 'An error occurred'}), 500

@app.route('/edit/<user_id>', methods=['PUT'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def edit_user_with_id(user_id):
    try:
        current_user_id = get_jwt_identity()
        if not current_user_id:
            return jsonify({'message': 'Invalid user'}), 401

        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404

        # Update user data based on the request JSON
        updated_data = request.get_json()
        if 'first_name' in updated_data:
            user.first_name = updated_data['first_name']
        if 'last_name' in updated_data:
            user.last_name = updated_data['last_name']
        if 'email' in updated_data:
            user.email = updated_data['email']
        if 'phone_number' in updated_data:
            user.phone_number = updated_data['phone_number']
        # Update other fields as needed
        # if 'has_paid' in updated_data:
        #     # Check if the has_paid status is being updated to True
        #     if updated_data['has_paid'] and not user.has_paid:
        #         user.has_paid = True

        #         # Check if the user has a referrer and update their earnings
        #         if user.referred_by_id:
        #             referrer = User.query.get(user.referred_by_id)
        #             if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
        #                 referrer.earnings += 100
        #                 db.session.add(referrer)

        if 'has_paid' in updated_data:
            # Check if the user has already paid
            if user.has_paid:
                return jsonify({'message': 'User has already paid'}), 400

            # If the payment status is being updated to True
            if updated_data['has_paid'] and not user.has_paid:
                user.has_paid = True

                # Check if the user has a referrer and update their earnings
                if user.referred_by_id:
                    referrer = User.query.get(user.referred_by_id)
                    if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                        referrer.earnings += 100
                        db.session.add(referrer)

        if 'has_not_paid' in updated_data:
            user.has_paid = False

        if 'earnings' in updated_data:
            user.earnings = updated_data['earnings']
        if 'is_email_verified' in updated_data:
            user.is_email_verified = updated_data['is_email_verified']
        if 'referrer' in updated_data:
            user.referred_by_id = updated_data['referrer']
        if 'account' in updated_data:
            user.account = updated_data['account']
        if 'role_id' in updated_data:
            user.role_id = updated_data['role_id']
        if 'password' in updated_data:
            new_password = updated_data['password']
            hashed_password = bcrypt_sha256.hash(new_password)
            user.password = hashed_password

        db.session.commit()

        return jsonify({'message': f'User data updated successfully for {user.email}'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/update-payment-status', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def update_payment_status():
    try:
        # Fetch users with has_paid status set to False
        unpaid_users = User.query.filter_by(has_paid=False).all()

        print(f"""
                    ################################################
                    ################################################
                    ################################################
                    ################################################
                            Starting the update of payment
                    ################################################
                    ################################################
                    ################################################
                    ################################################
                    ################################################
                    ################################################
                    """)
        # Loop through each unpaid user
        for user in unpaid_users:
            # Prepare data to send to the API
            data = {
                # Replace with your actual encryption key
                'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
                'transaction_ref': user.id  # Use user ID as the transaction reference
            }

            # Send request to the API
            response = requests.post(
                'https://api.marasoftpay.live/checktransaction', data=data)

            # Parse the response JSON
            response_data = response.json()

            # Print user ID for tracking
            print(f"Processing user with ID: {user.id}")

            # Check if the user has already paid
            if user.has_paid:
                print(f"User already paid: {user.id}")
                continue  # Skip processing this user

            # Check if the transaction was successful and update user's payment status
            if response_data.get('status') == True and response_data.get('transaction_status', '') == 'Successful':
                user.has_paid = True
                db.session.add(user)
                db.session.commit()

                # Check if the user has a referrer and update their earnings
                if user.referred_by_id:
                    referrer = User.query.get(user.referred_by_id)
                    if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                        referrer.earnings += 100
                        db.session.add(referrer)
                        db.session.commit()

                # Save successful payment
                successful_payment = SuccessfulPayment(
                    user_id=user.id,
                    transaction_reference=response_data.get('merchant_ref'),
                    payment_amount=response_data.get(
                        'transaction_amount')  # Adjust this accordingly
                )
                db.session.add(successful_payment)
                db.session.commit()

                # Update earnings for executives in the user's state
                if user.state:
                    executives = User.query.filter_by(state=user.state).all()
                    for executive in executives:
                        if executive.role and executive.role.role_name == 'Executives':
                            executive.earnings += 50
                            db.session.add(executive)
                            db.session.commit()

                if user.referred_by_id:
                    print(
                        f"User payment successful: {user.email}, updated paymend for the executive of {executive.state}. Earnings distributed to the referrer {referrer.email}")
                else:
                    print(
                        f"User payment successful: {user.email}, updated paymend for the executive of {executive.state}.")

            else:
                print(f"User payment failed: {user.id}")

        return jsonify({'message': 'Payment statuses updated successfully'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/process-payment/<transaction_ref>', methods=['GET'])
def process_payment(transaction_ref):
    user = User.query.filter_by(id=transaction_ref).first()

    if user.has_paid:
        return jsonify(message="User has paid already")

    try:
        # Prepare data to send to the Marasoft API
        data = {
            'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
            'transaction_ref': transaction_ref
        }

        # Send request to the Marasoft API as form data
        response = requests.post(
            'https://api.marasoftpay.live/checktransaction', data=data)

        # Print the JSON response received from Marasoft API
        print("Marasoft API Response:", response.text)
        print()
        print()

        # Parse and return the response
        response_data = response.json()

        if 'status' in response_data and not response_data['status']:
            error_message = response_data['error']
            return jsonify(message=error_message)

        if isinstance(response_data, list):
            for data_entry in response_data:
                if not data_entry['status']:
                    return jsonify(message="Failed transaction")
                process_data_entry(data_entry, user)
        elif isinstance(response_data, dict):
            if not response_data['status']:
                error_message = response_data['error']
                return jsonify(message=error_message)
            process_data_entry(response_data, user)
        else:
            return jsonify(message="Invalid API response format"), 500

        return jsonify(message="Successful payment and earnings distribution done"), 200

    except ValueError:
        return jsonify({'message': 'Invalid API response'}), 500
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


@app.route("/transfer", methods=["POST"])
@jwt_required()
def initialize_tranfer_payment():
    try:
        # Retrieve the user from the database
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        # Check if the user exists
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Prepare the form data payload
        payload = {
            "enc_key": "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
            "amount": 200,  # Update this with the actual amount
            "transaction_ref": user.id,
        }

        # Make a payment request to Marasoft API to initiate payment
        response = requests.post(
            "https://api.marasoftpay.live/generate_dynamic_account/",
            data=payload,
        )

        data = response.json()
        print(f"""
              #######################
              #######################
                      Marasoft:
                        {data}
              #######################
              #######################
                 User Id {user.id}
              #######################
              #######################
                 User Email {user.email}
              #######################
                        
              """)

        if response.status_code == 200 and data["status"] == True:
            return jsonify({
                "account_number": data["account_number"],
                "account_name": data["account_name"],
                "bank_name": data["bank_name"],
            })
        else:
            error_message = data.get("error") if data.get(
                "error") else "Payment initiation failed"
            print("Payment initiation failed:", error_message)
            return jsonify({"error": error_message}), 500

    except Exception as e:
        print("Payment initiation failed:", str(e))
        return jsonify({"error": "Payment initiation failed"}), 500


# @app.route('/check-user-payment', methods=['GET'])
# @jwt_required()
# def process_user_payment():
#     user_id = get_jwt_identity()
#     user = User.query.filter_by(id=user_id).first()

#     if user.has_paid:
#         return jsonify(message="User has paid already")

#     try:
#         # Prepare data to send to the Marasoft API
#         data = {
#             'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
#             'transaction_ref': user.id
#         }

#         # Send request to the Marasoft API as form data
#         response = requests.post(
#             'https://api.marasoftpay.live/checktransaction', data=data)

#         # Print the JSON response received from Marasoft API
#         print("Marasoft API Response:", response.text)
#         print()
#         print()

#         # Parse and return the response
#         # ...
#         try:
#             response_data = response.json()

#             if 'status' in response_data and not response_data['status']:
#                 error_message = response_data['error']
#                 return jsonify(message=error_message)

#             for data_entry in response_data:
#                 if not data_entry['status']:
#                     return jsonify(message="Failed transaction")
#                 if data_entry['status'] and data_entry['transaction_status'] == "Successful":
#                     user.has_paid = True
#                     db.session.add(user)
#                     db.session.commit()

#                     # Check if the user has a referrer and update their earnings
#                     if user.referred_by_id:
#                         referrer = User.query.get(user.referred_by_id)
#                         if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
#                             referrer.earnings += 100
#                             db.session.add(referrer)
#                             db.session.commit()

#                     # Save successful payment
#                     successful_payment = SuccessfulPayment(
#                         user_id=user.id,
#                         transaction_reference=data_entry.get('merchant_ref'),
#                         payment_amount=data_entry.get(
#                             'transaction_amount')  # Adjust this accordingly
#                     )
#                     db.session.add(successful_payment)
#                     db.session.commit()

#                     # Update earnings for executives in the user's state
#                     if user.state:
#                         users_state = user.state
#                         executives = User.query.filter(
#                             User.role_id == 3, User.state == users_state).first()
#                         for executive in executives:
#                             executive.earnings += 50
#                             db.session.add(executive)
#                         db.session.commit()

#             return jsonify(message="Successful payment and earnings distribution done"), 200
#         except ValueError:
#             return jsonify({'message': 'Invalid API response'}), 500
#         # ...

#     except Exception as e:
#         print(e)
#         return jsonify({'message': 'An error occurred'}), 500

@app.route('/check-user-payment', methods=['GET'])
@jwt_required()
def process_user_payment():
    user_id = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()

    if user.has_paid:
        return jsonify(message="User has paid already")

    try:
        # Prepare data to send to the Marasoft API
        data = {
            'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
            'transaction_ref': user.id
        }

        # Send request to the Marasoft API as form data
        response = requests.post(
            'https://api.marasoftpay.live/checktransaction', data=data)

        # Print the JSON response received from Marasoft API
        print("Marasoft API Response:", response.text)
        print()
        print()

        response_data = response.json()

        if isinstance(response_data, list):
            for data_entry in response_data:
                print(f"""
                      #####################
                      #####################
                      #####################
                         {data_entry}
                      #####################
                      #####################
                      #####################
                      """)
                if data_entry['transaction_status'] == "Successful":
                    process_data_entry(data_entry, user)
                else:
                    continue
        elif isinstance(response_data, dict):
            if response_data['status'] == True and response_data['transaction_status'] == "Successful":
                process_data_entry(response_data, user)
            else:
                return jsonify(message="Failed transaction 2"), 500
        else:
            return jsonify(message="Invalid API response format"), 500

        return jsonify(message="Successful payment and earnings distribution done"), 200

    except ValueError:
        return jsonify({'message': 'Invalid API response'}), 500
    except Exception as e:
        print(e)
        return jsonify({'message': 'An error occurred'}), 500


def process_data_entry(data_entry, user):
    if data_entry['status'] and data_entry['transaction_status'] == "Successful":
        user.has_paid = True
        db.session.add(user)
        db.session.commit()

        # Check if the user has a referrer and update their earnings
        if user.referred_by_id:
            referrer = User.query.get(user.referred_by_id)
            if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                referrer.earnings += 100
                db.session.add(referrer)
                db.session.commit()

        # Save successful payment
        successful_payment = SuccessfulPayment(
            user_id=user.id,
            transaction_reference=data_entry.get('merchant_ref'),
            payment_amount=data_entry.get(
                'transaction_amount')  # Adjust this accordingly
        )
        db.session.add(successful_payment)
        db.session.commit()

        # Update earnings for executives in the user's state
        if user.state:
            users_state = user.state
            executives = User.query.filter(
                User.role_id == 3, User.state == users_state).all()
            for executive in executives:
                executive.earnings += 50
                db.session.add(executive)
            db.session.commit()


@app.route('/delete-user/<user_id>', methods=['DELETE'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify(message=f'User {user.email} deleted successfully')
    else:
        return jsonify(message='User not found'), 404


@app.route('/delete-users', methods=['DELETE'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def delete_users():
    # JSON payload with user IDs to delete
    user_ids = request.json.get('user_ids')
    if not user_ids or not isinstance(user_ids, list):
        return jsonify(message='Invalid user IDs provided'), 400

    deleted_users = []
    for user_id in user_ids:
        user = User.query.filter_by(id=user_id).first()
        if user:
            # Delete related data first
            # Delete records in the OTP table
            OTP.query.filter_by(user_id=user_id).delete()

            # Delete records in the SuccessfulPayment table
            SuccessfulPayment.query.filter_by(user_id=user_id).delete()

            # Delete the user
            db.session.delete(user)
            deleted_users.append(user_id)

    db.session.commit()
    return jsonify(message='Users and related data deleted successfully', deleted_user_ids=deleted_users)


@app.route("/payments/total", methods=["GET"])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def get_total_paid_users():
    try:
        total_paid_users = User.query.filter_by(has_paid=True).count()
        return jsonify({"total_paid_users": total_paid_users}), 200
    except Exception as e:
        print("Error getting total paid users:", str(e))
        return jsonify({"error": "An error occurred while getting total paid users"}), 500


@app.route("/payments/total/interns", methods=["GET"])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def get_total_paid_interns():
    try:
        total_paid_interns = User.query.filter_by(
            has_paid=True, role_id=5).count()
        return jsonify({"total_paid_interns": total_paid_interns}), 200
    except Exception as e:
        print("Error getting total paid interns:", str(e))
        return jsonify({"error": "An error occurred while getting total paid interns"}), 500


@app.route("/payments/total/mobilizers", methods=["GET"])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def get_total_paid_mobilizers():
    try:
        total_paid_mobilizers = User.query.filter_by(
            has_paid=True, role_id=4).count()
        return jsonify({"total_paid_mobilizers": total_paid_mobilizers}), 200
    except Exception as e:
        print("Error getting total paid mobilizers:", str(e))
        return jsonify({"error": "An error occurred while getting total paid mobilizers"}), 500


@app.route('/process-unpaid-user-payments', methods=['GET'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def process_unpaid_user_payments():
    try:
        unpaid_users = User.query.filter_by(has_paid=False).all()

        if not unpaid_users:
            return jsonify(message="No unpaid users found"), 200

        print("Processing unpaid users...")

        for user in unpaid_users:
            try:
                # Prepare data to send to the Marasoft API
                data = {
                    'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
                    'transaction_ref': user.id
                }

                # Send request to the Marasoft API as form data
                response = requests.post(
                    'https://api.marasoftpay.live/checktransaction', data=data)

                # Print the JSON response received from Marasoft API
                print("Marasoft API Response:", response.text)

                response_data = response.json()

                if isinstance(response_data, list):
                    for data_entry in response_data:
                        process_marasoft_response(data_entry, user)
                elif isinstance(response_data, dict):
                    process_marasoft_response(response_data, user)

            except Exception as e:
                print(f"An error occurred for user {user.id}: {e}")

        return jsonify(message="Unpaid user payments processed"), 200

    except Exception as e:
        print(e)
        return jsonify(message="An error occurred"), 500


def process_marasoft_response(response_data, user):
    try:
        data_entry = response_data  # Since it's a dictionary response

        if data_entry['status'] and data_entry['transaction_status'] == "Successful":
            settled_amount = float(data_entry.get('settled_amount', 0))

            if settled_amount >= 1400:
                user.has_paid = True
                db.session.add(user)

                if user.referred_by_id:
                    referrer = User.query.get(user.referred_by_id)
                    if referrer and referrer.role and referrer.role.role_name == "Mobilizer":
                        referrer.earnings += 100
                        db.session.add(referrer)

                if user.state:
                    executives = User.query.filter(
                        User.role_id == 3, User.state == user.state).all()
                    for executive in executives:
                        executive.earnings += 50
                        db.session.add(executive)

                db.session.commit()

                print(f"User payment successful: {user.email}")
            else:
                print(f"User payment amount not sufficient: {user.email}")

        elif data_entry['transaction_status'] == "PENDING":
            print(f"User payment pending: {user.email}")
        else:
            print(f"User payment failed: {user.email}")

    except Exception as e:
        print(f"An error occurred processing Marasoft response: {e}")
        print(
            f"Unable to update payment for email: {user.email}, name: [first_Name:{user.first_name}, Last_Name: {user.last_name}] due to invalid Transaction")
        print()
        print()


@app.route("/check", methods=['GET'])
def check():
    return jsonify(message="MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3")


selected_bank_code = None  # To store the selected bank code for the user


@app.route('/get-banks', methods=['GET'])
def get_banks():
    try:
        response = requests.get(
            f'{MARASOFT_API_BASE}/getbanks', params={'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3"})
        data = response.json()
        if data['status'] == 'success':
            banks = data['data']['banks']
            return jsonify({'message': 'Banks fetched successfully', 'banks': banks}), 200
        else:
            return jsonify({'message': 'Failed to fetch banks'}), 500
    except Exception as e:
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/select-bank', methods=['POST'])
def select_bank():
    global selected_bank_code
    try:
        selected_bank_code = request.form.get('bank_code')
        return jsonify({'message': 'Bank selected successfully'}), 200
    except Exception as e:
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/verify-account', methods=['POST'])
def verify_account():
    try:
        account_number = request.form.get('account_number')
        bank_code = request.form.get('bank_code')

        if bank_code is None:
            return jsonify({'message': 'No bank selected'}), 400

        resolvebank_data = {
            'enc_key': "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
            'bank_code': bank_code,
            'account_number': account_number
        }
        resolvebank_response = requests.post(
            f'{MARASOFT_API_BASE}/resolvebank', data=resolvebank_data)
        resolvebank_data = resolvebank_response.json()

        if resolvebank_data['status'] == True:
            return jsonify({'message': 'Account is valid', 'account_name': resolvebank_data['data']['account_name']}), 200
        else:
            return jsonify({'message': 'Invalid bank account'}), 400
    except Exception as e:
        return jsonify({'message': 'An error occurred'}), 500


@app.route('/make-transfer', methods=['POST'])
@jwt_required()
def make_transfer():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()

        bank_code = request.form.get('bank_code')
        account_number = request.form.get('account_number')
        amount = request.form.get('amount')
        description = request.form.get('description')

        print(bank_code)
        print(account_number)
        print(amount)
        print(description)

        # Prepare transfer data
        transfer_data = {
            "enc_key": "MSFT_Enc_3P7BO5B5ZIE5RXL543IJV0SBXSDO7B3",
            "bank_code": bank_code,
            "account_number": account_number,
            "amount": amount,
            "description": description,
            "transactionRef": user.id,
            "currency": "NGN"
        }

        # Make the transfer
        transfer_response = requests.post(
            f'{MARASOFT_API_BASE}/createtransfer', data=transfer_data)
        transfer_data = transfer_response.json()

        user_amount_withdrawn = float(amount)

        if transfer_data.get('status') == "success":
            user.earnings -= user_amount_withdrawn
            db.session.commit()
            return jsonify({'message': 'Transfer successful'}), 200
        else:
            print(transfer_data)
            return jsonify({"message": f"{transfer_data}"}), 500
    except Exception as e:
        return jsonify({'message': 'An error occurred'}), 500


if __name__ == "__main__":
    app.run(debug=True)
