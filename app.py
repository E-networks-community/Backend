from functools import wraps
from urllib.parse import urlencode
import uuid
from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, session
# from asgiref.wsgi import WsgiToAsgi
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_session import Session
from models import SuccessfulPayment
from config import ApplicationConfig
from werkzeug.utils import secure_filename
from models import Role, db, User, create_roles
import os
import requests
import string
import random
from flask_mail import Mail, Message
import base64

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
#
jwt = JWTManager(app)
app.config['MAIL_SERVER'] = 'smtp.elasticemail.com'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'coldnightdev@gmail.com'
app.config['MAIL_PASSWORD'] = "DA79E471E994C2FBEC5BB9F44ABDF78CF139"
app.config['MAIL_USE_TLS'] = True
app.config['DATABASE_INITIALIZED'] = False
mail = Mail(app)
server_session = Session(app)
db.init_app(app)
with app.app_context():
    if not app.config['DATABASE_INITIALIZED']:
        db.create_all()
        app.config['DATABASE_INITIALIZED'] = True
        #
    else:
        # If the database has already been initialized, create roles only
        with app.app_context():
            db.drop_all()
            db.create_all()
####################################################################
####################################################################
####################################################################
####################################################################
####################################################################
######## Setting a concurent function to be run per request ########


@app.after_request
def add_cors_headers(response):
    # Replace with your frontend domain
    frontend_domain = 'https://www.enetworksagencybanking.com.ng/'
    response.headers['Access-Control-Allow-Origin'] = frontend_domain
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


####################################################################
####################################################################
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
####################################################################
####################################################################
####################################################################
####################################################################
################## Function to save profile Image ##################


def save_profile_image(image, user_id):
    filename = secure_filename(image.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(save_path)

    # Read the saved image file
    with open(save_path, 'rb') as file:
        image_data = file.read()

    # Encode the image data as base64
    base64_image = base64.b64encode(image_data).decode('utf-8')

    # Update the user's profile_image field with the base64 encoded image
    user = User.query.filter_by(id=user_id).first()
    user.profile_image = base64_image
    db.session.commit()

    return filename
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


@app.route('/send_email')
def send_test_email():
    recipient_email = 'coldnightdev@gmail.com'
    email_subject = 'E-network Email Verification'
    template = 'verify_email'

    # Generate a random OTP (you can use your own method to generate the OTP)
    otp = str(random.randint(100000, 999999))

    # Call the send_email_with_otp function to send the email with the OTP
    if send_email_with_otp(recipient_email, email_subject, template, otp):
        print(f'Email with OTP ({otp}) sent successfully to {recipient_email}')
        return 'Email sent successfully'  # Return a valid response
    else:
        print('Failed to send email')
        return 'Failed to send email'  # Return a valid response

####################################################################
####################################################################
####################################################################
# Function to send OTP to user's email


def send_otp_to_email_for_verify(email, otp):
    subject = "E-networksCommunity Verify Emai;"

    msg_body = f"Dear user,\n\n" \
               f"Verify your Email: {email}\n" \
               f"Your OTP for Email verification is: {otp}\n\n" \
               f"Please use this OTP to Verify your password. If you didn't create this Request, " \
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


@app.route('/admin/register', methods=['POST'])
def register_admin():
    return register_user(role_name='Admin')


@app.route('/intern/register', methods=['POST'])
def register_intern():
    return register_user(role_name='Intern')


@app.route('/user/register', methods=['POST'])
def register_user():
    return register_user(role_name='User')


@app.route('/onboarder/register', methods=['POST'])
def register_onboarder():
    return register_user(role_name='Onboarder')

####################################################################
####################################################################
####################################################################
####################################################################
# Add referral_link as a parameter with a default value of None
# ... (previous code)


def register_user(role_name, referrer_id=None):
    data = request.json
    if not data:
        return jsonify(message='No data provided in the request'), 400

    # Extract user registration data from the JSON request
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    phone_number = data.get('phone_number')
    referral_code = data.get('referral_code')

    if not all([first_name, last_name, email, password, phone_number]):
        return jsonify(message='Missing required fields in the request'), 400

    # Check if the email is already in use
    if User.query.filter_by(email=email).first():
        return jsonify(message='Email already registered'), 409

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
    hashed_password = bcrypt.generate_password_hash(password)

    new_user_referral_code = generate_referral_code()

    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        phone_number=phone_number,
        referral_code=new_user_referral_code,
        role=role
    )

    if referrer_id is not None:
        new_user.referred_me = referrer_id

    try:
        db.session.add(new_user)
        db.session.commit()

        # Generate an OTP for email verification
        email_verification_otp = generate_otp()

        # Send the OTP to the user's email
        send_otp_to_email_for_verify(
            new_user.email, email_verification_otp)

        # Save the OTP in the user's session for verification later
        session['email_verification_otp'] = email_verification_otp

        new_user.referral_link = new_user.generate_referral_link()
        db.session.commit()

        return jsonify(message='User registered successfully'), 201
    except Exception as e:
        db.session.rollback()
        print("Error during user registration:", str(e))
        return jsonify(message='Failed to register user. Please try again later.'), 500


@app.route('/login', methods=["POST"])
def login():
    # full_name = request.json.get('full_name')
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if user is None:
        return jsonify({"error": "Unauthorized"}), 401

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Unauthorized"}), 401

    access_token = create_access_token(identity=user.id)

    # Return the user's role along with the access token
    return jsonify({"access_token": access_token, "role": user.role.role_name}), 200


@app.route('/edit-user/<user_id>', methods=['PATCH'])
@jwt_required()
@require_role(['Admin', 'Super Admin'])
def edit_user(user_id):
    current_user_id = get_jwt_identity()

    # Check if the current user has permission to edit users (e.g., Admin or Super Admin)
    # You can define the require_role decorator to check the user's role and permissions.

    # Get the user to be edited from the database
    user_to_edit = User.query.get(user_id)
    if not user_to_edit:
        return jsonify({"message": "User not found"}), 404

    # Make sure the current user has permission to edit this user (optional, if needed)
    # Example:

    # Get the data from the PATCH request
    data = request.json

    # Update the user's data
    # if 'full_name' in data:
    #     user_to_edit.full_name = data['full_name']

    if 'first_name' in data:
        user_to_edit.first_name = data['first_name']

    # if 'last_name' in data:
    #     user_to_edit.last_name = data['last_name']

    if 'email' in data:
        user_to_edit.email = data['email']

    # if 'phone_number' in data:
    #     user_to_edit.phone_number = data['phone_number']
    # Add more fields as needed...

    # Commit the changes to the database
    db.session.commit()

    return jsonify({"message": f"User {user_id} data updated successfully"}), 200


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    user_id = get_jwt_identity()

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

    # Return the user's data as a JSON response
    return jsonify(user_data), 200


@app.route('/verify-email', methods=['POST'])
@jwt_required()
def verify_email():
    data = request.form  # Use request.form instead of request.json
    email_verification_otp = data.get('otp')
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify(message='User not found'), 404

    email = user.email
    print(f"This is the user Email {email}")
    stored_otp = session.get('email_verification_otp')

    if not email_verification_otp or not email:
        return jsonify(message='OTP and email fields are required'), 400

    if stored_otp != email_verification_otp:
        return jsonify(message='Invalid OTP'), 401

    if user.is_email_verified == "True":
        return jsonify(message="You have already verified your email")

    user.is_email_verified = True
    db.session.commit()

    session.pop('email_verification_otp', None)

    return jsonify(message='Email verified successfully'), 200


@app.route('/resend-otp', methods=['POST'])
@jwt_required()  # Assuming you are using JWT for authentication
def resend_otp():
    user_id = get_jwt_identity()

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify(message='User not found'), 404

    email = user.email

    # Generate a new OTP
    email_verification_otp = generate_otp()

    # Send the OTP to the user's email
    send_otp_to_email_for_verify(
        email, email_verification_otp)

    # Save the OTP in the user's session for verification later
    session['email_verification_otp'] = email_verification_otp

    # Send the new OTP to the user's email (you can implement this using an email service)
    return jsonify(message='New OTP sent successfully'), 200


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


# @app.route('/users', methods=['GET'])
# def get_all_users():
#     users = User.query.all()
#     user_data = [{
#         'id': user.id,
#         # 'full_name': user.full_name,
#         'first_name': user.first_name,
#         'last_name': user.last_name,
#         'email': user.email,
#         'profile_image': user.profile_image,
#         'has_paid': user.has_paid,
#         'role': user.role.role_name,
#         'created_at': user.created_at,
#         'modified_at': user.modified_at,
#         "is_email_verified": user.is_email_verified
#     } for user in users]
#     return jsonify(user_data)

@app.route('/users', methods=['GET'])
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


# @app.route('/users/<user_id>', methods=['GET'])
# def get_user_by_id(user_id):
#     user = User.query.get(user_id)
#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     user_data = {
#         'id': user.id,
#         # 'full_name': user.full_name,
#         'first_name': user.first_name,
#         'last_name': user.last_name,
#         'email': user.email,
#         # 'profile_pic': user.profile_pic,
#         "earnings": user.earnings,
#         'role': user.role.role_name if user.role else None,
#         'created_at': user.created_at,
#         'modified_at': user.modified_at,
#         "is_email_verified": user.is_email_verified,
#         "refered_by_id": user.ref
#     }

#     return jsonify(user_data)

@app.route('/users/<user_id>', methods=['GET'])
def get_user_by_id(user_id):
    try:
        user = User.query.get(user_id)
        if user:
            user_data = {
                'id': user.id,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'profile_image': user.profile_image,
                "earnings": user.earnings,
                'role': user.role.role_name if user.role else None,
                'created_at': user.created_at,
                'modified_at': user.modified_at,
                "is_email_verified": user.is_email_verified
            }
            return jsonify(user_data), 200
        else:
            return jsonify(message='User not found'), 404
    except Exception as e:
        print(e)
        return jsonify(message='An error occurred while fetching the user'), 500


@app.route('/referral/<referral_code>', methods=['POST'])
def register_with_referral(referral_code):
    data = request.json
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    phone_number = data.get('phone_number')

    if not all([email, password, first_name, last_name, phone_number]):
        return jsonify(message='Missing required fields in the request'), 400

    # Check if the referral code exists and get the referrer user
    referrer = User.query.filter_by(referral_code=referral_code).first()
    if not referrer:
        return jsonify(message='Invalid referral code provided'), 400

    if User.query.filter_by(email=email).first():
        return jsonify(message='Email already registered'), 409

    # Call the modified register_user function with the referrer ID
    result = register_user('User', referrer_id=referrer)

    return jsonify(message="Register complete"), 200


@app.route('/get/<referral_code>', methods=['GET'])
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
        transaction_reference = str(uuid.uuid4())

        # verification_token = generate_verification_token(
        #     user_id, transaction_reference)

        # Prepare the data payload
        payload = {
            "data": {
                "public_key": "MSFT_test_40M0277A5ADIAQPHIB6WIPYW7K00QUH",
                "request_type": "test",
                "merchant_tx_ref": transaction_reference,
                # Manually construct the redirect_url with query parameters
                "redirect_url": f"http://localhost:5000/pay/{user_id}/verify",
                "name": user.first_name,
                "email_address": user.email,
                "phone_number": user.phone_number,
                "amount": "1500",
                "currency": "NGN",
                "user_bear_charge": "no",
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

            # Remove the extra "?" from the redirect_url before the "status" parameter
            redirect_url = f"http://localhost:5000/pay/{user_id}/verify"
            # Update the user's payment reference in the database
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
    # verification_token = request.args.get("token")

    print("Received values:")
    # print("Status:", status)
    print("Transaction Reference:", transaction_reference)
    print("Payment Reference:", payment_reference)
    # print("Verification Token:", verification_token)

    # Check if the required parameters are missing
    if not status or not transaction_reference or not payment_reference:
        return jsonify({"error": "Missing required parameters"}), 400

    # Verify the verification token
    # if not verify_verification_token(user_id, transaction_reference, verification_token):
    #     return jsonify({"error": "Invalid verification token"}), 400

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
                return redirect("https://www.enetworksagencybanking.com.ng/user/dashboard")

            # Save the successful payment record to prevent duplicate earnings updates
            successful_payment = SuccessfulPayment(
                user_id=user_id,
                transaction_reference=transaction_reference,
                payment_amount=1500  # Change this to the actual payment amount
            )
            db.session.add(successful_payment)
            db.session.commit()

            # Update the user's payment status if the payment is successful
            user.has_paid = True
            # Set the payment reference as the transaction reference
            user.payment_reference = transaction_reference
            db.session.commit()

            # Check if the user was referred by another user
            if user.referred_me:
                # Get the referrer's ID from the 'referred_me' attribute
                referrer_id = user.referred_me.id
                referrer = User.query.get(referrer_id)
                if referrer:
                    # Add 10% of the payment amount to the referrer's earnings for every successful payment
                    payment_amount = 1500  # Change this to the actual payment amount
                    referrer.add_earnings(payment_amount * 0.1)

                    # Commit the changes to the database
                    try:
                        db.session.commit()
                    except Exception as e:
                        db.session.rollback()
                        print("Error updating referrer's earnings:", str(e))

            # Redirect to the desired URL or return a response indicating the payment was successful
            return redirect("https://www.enetworksagencybanking.com.ng/user/dashboard")

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


@app.route("/update_profile_image", methods=["POST"])
@jwt_required()
def update_profile_image():
    # user_id = session.get("user_id")
    user_id = get_jwt_identity()

    if not user_id:
        return jsonify({"error": "unauthorized"}), 401

    user = User.query.filter_by(id=user_id).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    profile_image = request.files.get("profile_image")

    # Process profile image upload
    if profile_image:
        profile_image_filename = save_profile_image(profile_image, user.id)
        user.profile_image = profile_image_filename
        db.session.commit()
    else:
        return jsonify({"error": "No profile image provided"}), 400

    # Read the image file and encode it as Base64
    try:
        with open(profile_image_filename, "rb") as file:
            encoded_image = base64.b64encode(file.read()).decode("utf-8")
    except Exception as e:
        return jsonify({"error": "Failed to read and encode profile image"}), 500

    return redirect("https://www.enetworksagencybanking.com.ng/user/dashboard")


@app.route("/logout", methods=["POST"])
def logout():
    # Clear the token on the client-side (e.g., remove from local storage or delete the token cookie)
    # No server-side token handling is required
    return jsonify({"message": "Logged out successfully"}), 200


if __name__ == "__main__":
    app.run(debug=True)
