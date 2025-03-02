from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  
    parcels = db.relationship('Parcel', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Parcel(db.Model):
    __tablename__ = 'parcels'
    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(50), unique=True, nullable=False)
    pickup_location = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Pending') 
    current_location = db.Column(db.String(200), nullable=True)
    weight = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    cost = db.Column(db.Float, nullable=True)
    delivery_speed = db.Column(db.String(50), nullable=True)  
    cancel_date = db.Column(db.DateTime, nullable=True)  # New field for cancellation date
    cancel_reason = db.Column(db.String(200), nullable=True)  # New field for cancellation reason
    refund_status = db.Column(db.String(50), nullable=True, default='Pending')  # New field for refund status

    def to_dict(self):
        return {
            'id': self.id,
            'tracking_id': self.tracking_id,
            'pickup_location': self.pickup_location,
            'destination': self.destination,
            'status': self.status,
            'current_location': self.current_location,
            'weight': self.weight,
            'description': self.description,
            'user_id': self.user_id,
            'cost': self.cost,
            'delivery_speed': self.delivery_speed,
            'cancel_date': self.cancel_date.isoformat() if self.cancel_date else None,  # Format date for JSON
            'cancel_reason': self.cancel_reason,
            'refund_status': self.refund_status
        }