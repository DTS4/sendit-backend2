from flask import Flask, request, jsonify, abort
from flask_migrate import Migrate
from flask_cors import CORS
from server.config import Config
from server.models import db, User, Parcel, Item
from functools import wraps
import jwt
import datetime
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import string
import random
from dotenv import load_dotenv
import os
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, resources={r"/*": {"origins": "*"}})

# Helper function for JWT authentication with role-based access control
def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                abort(401, description="Token is missing!")
            try:
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = User.query.get(data['user_id'])
                if roles and current_user.role not in roles:
                    abort(403, description="You do not have permission to access this resource.")
            except jwt.ExpiredSignatureError:
                abort(401, description="Token has expired!")
            except jwt.InvalidTokenError:
                abort(401, description="Token is invalid!")
            except Exception as e:
                print(f"Token error: {e}")
                abort(401, description="Token is invalid!")
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

# Function to calculate cost (without Google Maps API)
def calculate_cost(distance, weight):
    try:
        distance = float(distance)
        weight = float(weight)
    except (ValueError, TypeError):
        raise ValueError("Distance and weight must be valid numbers.")

    rate_per_km = 1.5  # $1.5 per kilometer per kilogram
    return round(distance * rate_per_km * weight, 2)

# Function to calculate distance using OSRM API
def calculate_osrm_distance(pickup_location, delivery_location):
    try:
        def geocode_location(address):
            url = f"https://nominatim.openstreetmap.org/search?q={address}&format=json&limit=1"
            response = requests.get(url)
            if response.status_code != 200 or not response.json():
                raise ValueError(f"Location not found: {address}")
            data = response.json()
            return {
                "lat": float(data[0]['lat']),
                "lon": float(data[0]['lon'])
            }

        pickup_coords = geocode_location(pickup_location)
        delivery_coords = geocode_location(delivery_location)

        osrm_url = f"http://router.project-osrm.org/route/v1/driving/{pickup_coords['lon']},{pickup_coords['lat']};{delivery_coords['lon']},{delivery_coords['lat']}?overview=false"
        osrm_response = requests.get(osrm_url)
        if osrm_response.status_code != 200 or 'routes' not in osrm_response.json():
            raise ValueError("Route could not be calculated")

        osrm_data = osrm_response.json()

        distance_km = osrm_data['routes'][0]['legs'][0]['distance'] / 1000
        return round(distance_km, 2)  # Return distance rounded to 2 decimal places

    except Exception as e:
        print(f"Error calculating distance: {e}")
        return None

# Function to generate reset token
def generate_reset_token(length=32):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Function to send email
def send_email(subject, recipient, body):
    sender_email = os.getenv("EMAIL_ADDRESS")
    sender_password = os.getenv("EMAIL_PASSWORD")
    smtp_server = os.getenv("SMTP_SERVER", "smtp.mailtrap.io")
    smtp_port = int(os.getenv("SMTP_PORT", 2525))

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False


def send_email_notification(email, subject, content):
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        message = Mail(
            from_email=os.getenv("EMAIL_ADDRESS"),
            to_emails=email,
            subject=subject,
            plain_text_content=content
        )
        sg.send(message)
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

# Routes

@app.route('/')
def home():
    return "Parcel Delivery Backend"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return '''
               Username or Email:     Password:     Login   
        '''
    elif request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        if not data.get('username') or not data.get('password'):
            return jsonify({
                'error': 'Username/Email and password are required.'
            }), 400

        user = User.query.filter((User.username == data['username']) | (User.email == data['username'])).first()

        if user and user.check_password(data['password']):
            token = jwt.encode({
                'user_id': user.id,
                'role': user.role,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, app.config['SECRET_KEY'])
            return jsonify({
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
            }), 200
        return jsonify({
            'error': 'Invalid username/email or password.'
        }), 401

@app.route('/logout', methods=['GET', 'POST'])
@token_required()
def logout(current_user):
    if request.method == 'GET':
        return jsonify({'message': 'Logout endpoint. Use POST to logout.'}), 200
    elif request.method == 'POST':
        return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json()

        if not all([data.get('username'), data.get('email'), data.get('password'), data.get('confirm_password')]):
            return jsonify({'error': 'All fields are required.'}), 400

        if data['password'] != data['confirm_password']:
            return jsonify({'error': 'Passwords do not match.'}), 400

        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists.'}), 400

        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists.'}), 400

        user = User(
            username=data['username'],
            email=data['email'],
            phone_number=data.get('phone_number'),  # Optional phone number
            role=data.get('role', 'user')
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'phone_number': user.phone_number,
                'role': user.role
            }
        }), 201

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data.get('email'):
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    reset_token = generate_reset_token()
    user.reset_token = reset_token
    db.session.commit()

    reset_link = f"http://localhost:3000/reset-password/{reset_token}"
    email_subject = "Password Reset Request"
    email_body = f"Click the link to reset your password: {reset_link}"

    if send_email(email_subject, user.email, email_body):
        return jsonify({'message': 'Password reset email sent'}), 200
    else:
        return jsonify({'error': 'Failed to send email'}), 500

@app.route('/reset-password/', methods=['POST'])
def reset_password(reset_token):
    data = request.get_json()
    if not data.get('password'):
        return jsonify({'error': 'Password is required'}), 400

    user = User.query.filter_by(reset_token=reset_token).first()
    if not user:
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    user.set_password(data['password'])
    user.reset_token = None
    db.session.commit()

    return jsonify({'message': 'Password reset successful'}), 200

# Fetch Parcels Route
@app.route('/parcels', methods=['GET'], endpoint='fetch_parcels')  # Unique endpoint name
def fetch_parcels():
    status = request.args.get('status')
    user_id = request.args.get('user_id')

    query = Parcel.query
    if status:
        query = query.filter_by(status=status)
    if user_id:
        query = query.filter_by(user_id=user_id)

    parcels = query.all()
    return jsonify([parcel.to_dict() for parcel in parcels])

# Create Parcel Route
@app.route('/parcels', methods=['POST'], endpoint='create_parcel')  # Unique endpoint name
def create_parcel():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        required_fields = ['pickup_location', 'destination', 'weight', 'delivery_speed']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        distance = data.get('distance')
        if distance is None or distance == "":
            distance = calculate_osrm_distance(data['pickup_location'], data['destination'])
            if distance is None:
                return jsonify({'error': 'Failed to calculate distance'}), 400

        try:
            weight = float(data['weight'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Weight must be a valid number'}), 400

        cost = calculate_cost(distance, weight)

        parcel = Parcel(
            tracking_id=f"TRK{random.randint(100000, 999999)}",
            pickup_location=data['pickup_location'],
            destination=data['destination'],
            distance=distance,
            weight=weight,
            description=data.get('description', ''),
            user_id=data.get('user_id', 1),  # Default user_id for testing
            cost=cost,
            delivery_speed=data['delivery_speed'],
            status='Pending'
        )
        db.session.add(parcel)
        db.session.commit()

        user = User.query.get(parcel.user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404

        email_subject = "Order Confirmation"
        email_content = (
            f"Dear {user.username},\n\n"
            f"Your parcel has been created successfully.\n"
            f"Tracking ID: {parcel.tracking_id}\n"
            f"Pickup Location: {parcel.pickup_location}\n"
            f"Destination: {parcel.destination}\n"
            f"Distance: {parcel.distance} km\n"
            f"Weight: {parcel.weight} kg\n"
            f"Cost: ${parcel.cost}\n"
            f"Delivery Speed: {parcel.delivery_speed}\n\n"
            f"Thank you for choosing our service!"
        )

        send_email_notification(user.email, email_subject, email_content)

        return jsonify({
            'message': 'Parcel created successfully',
            'parcel': parcel.to_dict()
        }), 201

    except Exception as e:
        print(f"Error creating parcel: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Cancel Parcel Route
@app.route('/parcels/<int:parcel_id>/cancel', methods=['POST'], endpoint='cancel_parcel')  # Unique endpoint name
def cancel_parcel(parcel_id):
    try:
        parcel = Parcel.query.get_or_404(parcel_id)

        if parcel.status == 'Cancelled':
            return jsonify({'error': 'This parcel is already cancelled'}), 400

        if parcel.status == 'Delivered':
            return jsonify({'error': 'You cannot cancel a delivered parcel'}), 400

        data = request.get_json()
        if not data or not data.get('cancel_reason'):
            return jsonify({'error': 'Cancellation reason is required'}), 400

        parcel.status = 'Cancelled'
        parcel.cancel_date = datetime.datetime.utcnow()
        parcel.cancel_reason = data['cancel_reason']
        db.session.commit()

        return jsonify({
            'message': 'Parcel cancelled successfully',
            'parcel': parcel.to_dict()
        }), 200

    except Exception as e:
        print(f"Error cancelling parcel: {e}")
        return jsonify({'error': 'Failed to cancel parcel'}), 500

# Get Cancelled Parcels Route
@app.route('/parcels/cancelled', methods=['GET'], endpoint='get_cancelled_parcels')  # Unique endpoint name
def get_cancelled_parcels():
    try:
        user_id = request.args.get('user_id', type=int)
        if not user_id:
            return jsonify({'error': 'User ID is required'}), 400

        cancelled_parcels = Parcel.query.filter_by(user_id=user_id, status='Cancelled').all()

        parcels_data = [parcel.to_dict() for parcel in cancelled_parcels]
        return jsonify(parcels_data), 200
    except Exception as e:
        print(f"Error fetching cancelled parcels: {e}")
        return jsonify({'error': 'Failed to fetch cancelled parcels'}), 500

# Update Parcel Status (Admin Only)
@app.route('/parcels/<int:parcel_id>/update_status', methods=['POST'], endpoint='update_parcel_status')  # New admin-only route
@token_required(roles=['admin'])  # Ensure only admins can access this route
def update_parcel_status(current_user, parcel_id):
    try:
        parcel = Parcel.query.get_or_404(parcel_id)

        data = request.get_json()
        if not data or not data.get('status'):
            return jsonify({'error': 'Status is required'}), 400

        new_status = data['status'].strip().capitalize()

        valid_statuses = ['Pending', 'In Transit', 'Delivered']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400

        parcel.status = new_status
        db.session.commit()

        return jsonify({
            'message': 'Parcel status updated successfully',
            'parcel': parcel.to_dict()
        }), 200

    except Exception as e:
        print(f"Error updating parcel status: {e}")
        return jsonify({'error': 'Failed to update parcel status'}), 500

# Patch Parcel Route (Update other details)
@app.route('/parcels/<int:parcel_id>', methods=['PATCH'], endpoint='patch_parcel')  # Unique endpoint name
def patch_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    data = request.get_json()

    if 'status' in data:
        parcel.status = data['status']
    if 'current_location' in data:
        parcel.current_location = data['current_location']
    db.session.commit()
    return jsonify(parcel.to_dict())

# Delete Parcel Route
@app.route('/parcels/<int:parcel_id>', methods=['DELETE'], endpoint='delete_parcel')  # Unique endpoint name
def delete_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    db.session.delete(parcel)
    db.session.commit()
    return '', 204

# Stats Route
@app.route('/stats', methods=['GET'], endpoint='get_stats')  # Unique endpoint name
def get_stats():
    try:
        total_deliveries = Parcel.query.count()
        pending_orders = Parcel.query.filter_by(status='Pending').count()
        in_transit_orders = Parcel.query.filter_by(status='In Transit').count()
        delivered_orders = Parcel.query.filter_by(status='Delivered').count()

        return jsonify({
            'total_deliveries': total_deliveries,
            'pending_orders': pending_orders,
            'in_transit_orders': in_transit_orders,
            'delivered_orders': delivered_orders
        }), 200
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({'error': 'Failed to fetch statistics'}), 500

# Get User Details Route
@app.route('/user', methods=['GET'], endpoint='get_user_v1')  # Unique endpoint name
def get_user_v1():
    try:
        user_id = 1  # Replace with a valid user_id for testing
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role
        }), 200
    except Exception as e:
        print(f"Error fetching user details: {e}")
        return jsonify({'error': 'Failed to fetch user details'}), 500

# Update User Settings Route
@app.route('/settings', methods=['POST'], endpoint='update_settings')  # Unique endpoint name
def update_settings():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        user_id = 1  # Replace with a valid user_id for testing
        user = User.query.get(user_id)

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if 'email_notifications' in data:
            user.email_notifications = data['email_notifications']
        if 'dark_mode' in data:
            user.dark_mode = data['dark_mode']

        db.session.commit()
        return jsonify({'message': 'Settings updated successfully'}), 200
    except Exception as e:
        print(f"Error updating settings: {e}")
        return jsonify({'error': 'Failed to update settings'}), 500

# Get User Items Route
@app.route('/user/items', methods=['GET'], endpoint='get_user_items')  # Unique endpoint name
def get_user_items():
    try:
        user_id = 2  # Replace with a valid user_id for testing
        items = Item.query.filter_by(user_id=user_id).all()

        items_data = [item.to_dict() for item in items]
        return jsonify(items_data), 200
    except Exception as e:
        print(f"Error fetching user items: {e}")
        return jsonify({'error': 'Failed to fetch user items'}), 500

# Admin API User Route
@app.route('/api/user', methods=['GET'], endpoint='get_user_v2')  # Unique endpoint name
@token_required()
def get_user_v2(current_user):
    try:
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role
        }), 200
    except Exception as e:
        print(f"Error fetching user details: {e}")
        return jsonify({'error': 'Failed to fetch user details'}), 500

if __name__ == '__main__':
    app.run(debug=True)