from datetime import datetime
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import BigInteger, select, join

db = SQLAlchemy()


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True,
                      nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), index=True)
    role_id = db.Column(db.Integer, db.ForeignKey(
        'role.id'), nullable=False, index=True, default=2)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Admin {self.first_name} + {self.last_name}>"

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "phone_number": self.phone_number,
            "role_id": self.role_id,
            "created_at": str(self.created_at),
            "modified_at": str(self.modified_at),
        }


# Admin Logs
class AdminLog(db.Model):
    __tablename__ = 'adminlogs'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey(
        'admin.id'), nullable=False, index=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AdminLog {self.admin_id} + {self.action}>"

    def to_dict(self):
        return {
            "id": self.id,
            "admin_id": self.admin_id,
            "action": self.action,
            "timestamp": str(self.timestamp),
        }


class Hire(db.Model):
    __tablename__ = 'hires'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255),
                      nullable=False, index=True)
    phone_number = db.Column(db.String(20), index=True)
    active_contact_address = db.Column(db.String(255), index=True)
    state = db.Column(db.String(100), index=True)
    local_government = db.Column(db.String(100), index=True)
    ward = db.Column(db.String(100), index=True)
    guarantor_name = db.Column(db.String(100), index=True)
    guarantor_phone_number = db.Column(db.String(100), index=True)
    language = db.Column(db.String(100), index=True)
    position = db.Column(db.String(100), index=True)
    gender = db.Column(db.String(100), index=True)
    next_of_kin_name = db.Column(db.String(100), index=True)
    next_of_kin_phone_number = db.Column(db.String(100), index=True)
    next_of_kin_relationship = db.Column(db.String(100), index=True)
    next_of_kin_email = db.Column(db.String(100), index=True)
    profile_image = db.Column(db.TEXT, default=None, index=True)
    to_work_state = db.Column(db.String(100), index=True)
    hire_status = db.Column(db.String(100), index=True)
    agent_account_email = db.Column(db.String(100), index=True)
    agent_account_id = db.Column(db.String(100), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "phone_number": self.phone_number,
            "active_contact_address": self.active_contact_address,
            "state": self.state,
            "local_government": self.local_government,
            "ward": self.ward,
            "guarantor_name": self.guarantor_name,
            "guarantor_phone_number": self.guarantor_phone_number,
            "language": self.language,
            "position": self.position,
            "gender": self.gender,
            "next_of_kin_name": self.next_of_kin_name,
            "next_of_kin_phone_number": self.next_of_kin_phone_number,
            "next_of_kin_relationship": self.next_of_kin_relationship,
            "next_of_kin_email": self.next_of_kin_email,
            "profile_image": self.profile_image,
            "to_work_state": self.to_work_state,
            "hire_status": str(self.hire_status),
        }

    # function to return statistical data for the user in the AmonHires
    @classmethod
    def get_total_hires(cls):
        return cls.query.count()

    @classmethod
    def get_total_hires_per_state(cls, state_name):
        return cls.query.filter_by(state=state_name).count()

    @classmethod
    def get_total_hires_per_lga(cls, lga_name):
        return cls.query.filter_by(local_government=lga_name).count()

    @classmethod
    def get_total_hires_per_ward(cls, ward_name):
        return cls.query.filter_by(ward=ward_name).count()

    # function to return all the data aboce for total hires, state, lga and ward
    @classmethod
    def get_total_hires_data(cls):
        return {
            "total_hires": cls.get_total_hires(),
            # "total_hires_per_state": cls.get_total_hires_per_state(),
            # "total_hires_per_lga": cls.get_total_hires_per_lga(),
            # "total_hires_per_ward": cls.get_total_hires_per_ward(),
        }


class AmonHire(db.Model):
    __tablename__ = 'amonhires'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255),
                      nullable=False, index=True)
    phone_number = db.Column(db.String(20), index=True)
    active_contact_address = db.Column(db.String(255), index=True)
    state = db.Column(db.String(100), index=True)
    local_government = db.Column(db.String(100), index=True)
    ward = db.Column(db.String(100), index=True)
    guarantor_name = db.Column(db.String(100), index=True)
    guarantor_phone_number = db.Column(db.String(100), index=True)
    language = db.Column(db.String(100), index=True)
    position = db.Column(db.String(100), index=True)
    gender = db.Column(db.String(100), index=True)
    next_of_kin_name = db.Column(db.String(100), index=True)
    next_of_kin_phone_number = db.Column(db.String(100), index=True)
    next_of_kin_relationship = db.Column(db.String(100), index=True)
    next_of_kin_email = db.Column(db.String(100), index=True)
    profile_image = db.Column(db.TEXT, default=None, index=True)
    to_work_state = db.Column(db.String(100), index=True)
    hire_status = db.Column(db.String(100), index=True)
    agent_account_email = db.Column(db.String(100), index=True)
    agent_account_id = db.Column(db.String(100), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "phone_number": self.phone_number,
            "active_contact_address": self.active_contact_address,
            "state": self.state,
            "local_government": self.local_government,
            "ward": self.ward,
            "guarantor_name": self.guarantor_name,
            "guarantor_phone_number": self.guarantor_phone_number,
            "language": self.language,
            "position": self.position,
            "gender": self.gender,
            "next_of_kin_name": self.next_of_kin_name,
            "next_of_kin_phone_number": self.next_of_kin_phone_number,
            "next_of_kin_relationship": self.next_of_kin_relationship,
            "next_of_kin_email": self.next_of_kin_email,
            "profile_image": self.profile_image,
            "to_work_state": self.to_work_state,
            "hire_status": self.hire_status,
        }


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
    email = db.Column(db.String(255), unique=True,
                      nullable=False, index=True)  # Add index=True here
    password = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), index=True)
    referral_code = db.Column(
        db.String(10), unique=True, nullable=True, index=True)
    local_government = db.Column(db.String(100), index=True)
    state = db.Column(db.String(100), index=True)
    address = db.Column(db.String(255), index=True)
    bank_name = db.Column(db.String(255), index=True, nullable=True)
    referral_link = db.Column(
        db.String(255), unique=True, nullable=True, index=True)
    otps = db.relationship('OTP', backref='user', lazy='dynamic')
    # New column to store the referrer's ID
    referred_by_id = db.Column(db.String(36), db.ForeignKey(
        'user.id'), nullable=True, index=True)

    role_id = db.Column(db.Integer, db.ForeignKey(
        'role.id'), nullable=False, index=True)
    account = db.Column(BigInteger, index=True, nullable=True)
    enairaId = db.Column(db.String(255), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, default=datetime.utcnow)
    earnings = db.Column(db.Float, default=0.0, index=True)
    reserved_earnings = db.Column(db.Float, default=0.0, index=True)
    profile_image = db.Column(db.TEXT, default=None, index=True)
    is_email_verified = db.Column(db.Boolean, default=False, index=True)
    has_paid = db.Column(db.Boolean, default=False, index=True)
    referred_users = db.relationship('User', backref=db.backref(
        'referrer', remote_side=[id]), lazy='dynamic')

    mobilizer_intern_id = db.Column(
        db.String(50), nullable=True, unique=True, index=True)
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

    def get_total_paid_referrals(self):
        return self.referred_users.filter_by(has_paid=True).count()

    # Function to get total unpaid referrals
    def get_total_unpaid_referrals(self):
        return self.referred_users.filter_by(has_paid=False).count()

    # Function to get total verified referrals
    def get_total_verified_referrals(self):
        return self.referred_users.filter_by(is_email_verified=True).count()

    # Function to get total unverified referrals
    def get_total_unverified_referrals(self):
        return self.referred_users.filter_by(is_email_verified=False).count()

    def get_total_agents_referred(self):
        return self.referred_users.filter_by(role_id=6).count()

    def get_total_interns_referred(self):
        return self.referred_users.filter_by(role_id=5).count()

    def get_total_amount_withdrawn(self):
        total_paid_users = self.referred_users.filter_by(has_paid=True).all()
        total_amount_withdrawn = sum(
            user.earnings for user in total_paid_users)
        return min(total_amount_withdrawn, self.earnings)
        # 'min' is used to ensure the calculated value doesn't exceed the total earnings

    def get_all_time_earnings(self):
        total_paid_users = self.referred_users.filter_by(has_paid=True).count()
        total_amount_earned = total_paid_users * 100
        return total_amount_earned
        # 'min' is used to ensure the calculated value doesn't exceed the total earnings
#

    def to_dict(self):
        # Get the ID of the referrer or None if no referrer
        referred_me = self.referred_me.id if self.referred_me else None
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'has_paid': self.has_paid,
            'phone_number': self.phone_number,
            'referral_code': self.referral_code,
            'referral_link': self.referral_link,
            "referred_by_id": self.referred_by_id,
            'referred_me': referred_me,  # Set the referred_me attribute to the ID of the referrer
            'role_id': self.role_id,
            'role': self.role.role_name,
            'created_at': str(self.created_at),
            'modified_at': str(self.modified_at),
            'is_email_verified': str(self.is_email_verified),
            'earnings': self.earnings,
            'reserved_earnings': self.reserved_earnings,
            'account': self.account,
            'bank_name': self.bank_name,
            'profile_image': str(self.profile_image),
            'mobilizer_intern_id': self.mobilizer_intern_id,
            'total_referred_users': self.get_total_referred_users(),
            'total_paid_referrals': self.get_total_paid_referrals(),
            'total_unpaid_referrals': self.get_total_unpaid_referrals(),
            'total_verified_referrals': self.get_total_verified_referrals(),
            'total_unverified_referrals': self.get_total_unverified_referrals(),
            'total_amount_withdrawn': self.get_total_amount_withdrawn(),
            'total_amount_earned': self.get_all_time_earnings(),
            'total_agents_referred': self.get_total_agents_referred(),
            'total_interns_referred': self.get_total_interns_referred(),
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
