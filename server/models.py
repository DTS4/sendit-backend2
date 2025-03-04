from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    reset_token = db.Column(db.String(32), nullable=True)  # Ensure this exists
    email_notifications = db.Column(db.Boolean, default=True, nullable=False)
    dark_mode = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    parcels = db.relationship('Parcel', backref='user', lazy=True)
    items = db.relationship('Item', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Parcel(db.Model):
    __tablename__ = 'parcel'  # Table name is 'parcel'
    id = db.Column(db.Integer, primary_key=True)
    tracking_id = db.Column(db.String(50), unique=True, nullable=False)
    pickup_location = db.Column(db.String(200), nullable=False)
    destination = db.Column(db.String(200), nullable=False)
    distance = db.Column(db.Float, nullable=False)  # Distance in kilometers
    status = db.Column(db.String(50), nullable=False, default='Pending')
    current_location = db.Column(db.String(200), nullable=True)
    weight = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to 'user.id'
    cost = db.Column(db.Float, nullable=True)
    delivery_speed = db.Column(db.String(50), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'tracking_id': self.tracking_id,
            'pickup_location': self.pickup_location,
            'destination': self.destination,
            'distance': self.distance,
            'status': self.status,
            'current_location': self.current_location,
            'weight': self.weight,
            'description': self.description,
            'user_id': self.user_id,
            'cost': self.cost,
            'delivery_speed': self.delivery_speed
        }

class Item(db.Model):
    __tablename__ = 'item'  # Table name is 'item'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to 'user.id'
    name = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(200), nullable=False)
    rating = db.Column(db.Float, default=0.0)
    price = db.Column(db.Float, nullable=False)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'image': self.image_url,
            'rating': self.rating,
            'price': self.price,
            'purchaseDate': self.purchase_date.isoformat() if self.purchase_date else None,
        }