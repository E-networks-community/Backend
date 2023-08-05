from datetime import datetime
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import BigInteger, select, join

db = SQLAlchemy()


class SuccessfulPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        "user.id"), nullable=False)
    transaction_reference = db.Column(db.String(36), nullable=False)
    payment_amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)

    def __repr__(self):
        return f"<Role {self.role_name}>"


class User(db.Model):
    id = db.Column(db.String(36), primary_key=True,
                   default=lambda: str(uuid.uuid4()), unique=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20))
    referral_code = db.Column(db.String(10), unique=True, nullable=True)
    local_government = db.Column(db.String(100))
    state = db.Column(db.String(100))
    address = db.Column(db.String(255))
    referral_link = db.Column(db.String(255), unique=True, nullable=True)
    otps = db.relationship('OTP', backref='user', lazy='dynamic')
    # New column to store the referrer's ID
    referred_by_id = db.Column(
        db.String(36), db.ForeignKey('user.id'), nullable=True)

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    account = db.Column(BigInteger)
    enairaId = db.Column(BigInteger)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    earnings = db.Column(db.Float, default=0.0)
    profile_image = db.Column(db.TEXT, default=None)
    is_email_verified = db.Column(db.Boolean, default=False)
    has_paid = db.Column(db.Boolean, default=False)
    referred_users = db.relationship('User', backref=db.backref(
        'referrer', remote_side=[id]), lazy='dynamic')

    # Relationships
    role = db.relationship('Role', backref='users')
    referred_me = db.relationship(
        'User', remote_side=[id], backref='referred_by', overlaps="referred_users,referrer")

    @classmethod
    def get_total_users_per_state(cls, state_name):
        return cls.query.filter_by(state=state_name).count()

    @classmethod
    def get_total_registered_users(cls):
        return cls.query.count()

    def get_recent_referral_history(self, limit=10):
        # Get the recent referral history of the user
        history = db.session.query(
            User.first_name,
            User.last_name,
            User.referred_by_id,
            User.created_at
        ).filter(User.referred_by_id == self.id).order_by(
            User.created_at.desc()
        ).limit(limit).all()

        return history

    def to_dict(self):
        # Get the ID of the referrer or None if no referrer
        referred_me = self.referred_me.id if self.referred_me else None
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'has_paid': str(self.has_paid),
            'phone_number': self.phone_number,
            'referral_code': self.referral_code,
            'referral_link': self.referral_link,
            'referred_me': referred_me,  # Set the referred_me attribute to the ID of the referrer
            'role_id': self.role_id,
            'role': self.role.role_name,
            'created_at': str(self.created_at),
            'modified_at': str(self.modified_at),
            'is_email_verified': str(self.is_email_verified),
            'earnings': self.earnings,
            'profile_image': str(self.profile_image),
            # Add this line to include total_referred_users
            'total_referred_users': self.get_total_referred_users(),
            'total_registered_users': User.get_total_registered_users(),  # Total registered users
            'recent_referral_history': self.get_recent_referral_history(),  # Recent referral histor
        }

    def get_total_referred_users(self):
        return self.referred_users.count()

    def __repr__(self):
        return f"<User {self.first_name} + {self.last_name}>"

    def get_referral_list(self):
        # Get the referred users and their email verification status as a list of dictionaries
        referral_list = []
        for referred_user in self.referred_users:
            referral_list.append({
                'id': referred_user.id,
                'first_name': referred_user.first_name,
                'last_name': referred_user.last_name,
                'email': referred_user.email,
                'is_email_verified': str(referred_user.is_email_verified),
                'has_paid': str(referred_user.has_paid)
            })
        return referral_list

    def get_referral_history(self, limit=10):
        # Fetch the referral history for the user from the SuccessfulPayment table
        referral_history = SuccessfulPayment.query.filter_by(user_id=self.id).order_by(
            SuccessfulPayment.timestamp.desc()
        ).limit(limit).all()

        # Convert the referral history data to a list of dictionaries
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

        return referrals

    def generate_referral_link(self):
        if self.referral_code:
            return f"https://www.enetworksagencybanking.com.ng/referral/{self.referral_code}"
        else:
            return None

    def add_earnings(self, earnings_amount):
        self.earnings += earnings_amount
        db.session.commit()


def create_roles():
    roles_data = [
        {'role_name': 'Super Admin'},
        {'role_name': 'Admin'},
        {'role_name': 'Executives'},
        {'role_name': 'Mobilizer'},
        {'role_name': 'Intern'},
        {'role_name': 'Agent'}
    ]

    for role_data in roles_data:
        role_name = role_data['role_name']
        role = Role.query.filter_by(role_name=role_name).first()

        if not role:
            new_role = Role(**role_data)
            db.session.add(new_role)

    db.session.commit()


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<OTP for {self.email}>"
