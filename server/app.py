from flask import Flask, request, jsonify, abort
from flask_migrate import Migrate
from flask_cors import CORS
from server.config import Config
from server.models import db, User, Parcel, Item
from functools import wraps
from datetime import datetime
import jwt
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import string
import random
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for testing

# Helper function for JWT authentication with role-based access control
def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                abort(401, description="Token is missing!")
            try:
                # Remove 'Bearer ' prefix if present
                if token.startswith('Bearer '):
                    token = token.split(' ')[1]
                # Decode the token
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

# Routes
@app.route('/')
def home():
    return "Parcel Delivery Backend"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Return a simple HTML form for testing
        return '''
            <form method="post">
                <label for="username">Username or Email:</label>
                <input type="text" id="username" name="username"><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password"><br>
                <button type="submit">Login</button>
            </form>
        '''
    elif request.method == 'POST':
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        # Validate required fields
        if not data.get('username') or not data.get('password'):
            return jsonify({
                'error': 'Username/Email and password are required.'
            }), 400

        # Check if the input is an email or username
        user = User.query.filter((User.username == data['username']) | (User.email == data['username'])).first()

        if user and user.check_password(data['password']):
            token = jwt.encode({
                'user_id': user.id,
                'role': user.role,  # Include role in the token
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
        # Return a simple message for GET requests
        return jsonify({'message': 'Logout endpoint. Use POST to logout.'}), 200
    elif request.method == 'POST':
        # In a stateless JWT system, logout is handled client-side by deleting the token
        return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'GET':
        # Return a simple HTML form for testing
        return '''
            <form method="post">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username"><br>
                <label for="email">Email:</label>
                <input type="email" id="email" name="email"><br>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password"><br>
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password"><br>
                <button type="submit">Sign Up</button>
            </form>
        '''
    elif request.method == 'POST':
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form

        # Validate required fields
        if not data.get('username') or not data.get('email') or not data.get('password') or not data.get('confirm_password'):
            return jsonify({
                'error': 'Username, email, password, and confirm password are required.'
            }), 400

        # Check if passwords match
        if data['password'] != data['confirm_password']:
            return jsonify({
                'error': 'Passwords do not match.'
            }), 400

        # Check if username or email already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({
                'error': 'Username already exists.'
            }), 400
        if User.query.filter_by(email=data['email']).first():
            return jsonify({
                'error': 'Email already exists.'
            }), 400

        user = User(
            username=data['username'],
            email=data['email'],
            role=data.get('role', 'user')
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()

        # Return the user object with the role field
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
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

@app.route('/reset-password/<reset_token>', methods=['POST'])
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

@app.route('/parcels', methods=['GET'])
# @token_required()  # Temporarily commenting out the token_required decorator
def get_parcels():
    status = request.args.get('status')
    user_id = request.args.get('user_id')

    query = Parcel.query
    if status:
        query = query.filter_by(status=status)
    if user_id:
        query = query.filter_by(user_id=user_id)

    parcels = query.all()
    return jsonify([parcel.to_dict() for parcel in parcels])

@app.route('/parcels', methods=['POST'])
def create_parcel():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate required fields
        required_fields = ['pickup_location', 'destination', 'distance', 'weight', 'delivery_speed']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'{field.replace("_", " ").title()} is required'}), 400

        # Convert distance and weight to floats
        try:
            distance = float(data['distance'])
            weight = float(data['weight'])
        except (ValueError, TypeError):
            return jsonify({'error': 'Distance and weight must be valid numbers'}), 400

        # Calculate cost using the provided distance and weight
        cost = calculate_cost(distance, weight)

        # Create the parcel
        parcel = Parcel(
            tracking_id=f"TRK{random.randint(100000, 999999)}",  # Generate a random tracking ID
            pickup_location=data['pickup_location'],
            destination=data['destination'],
            distance=distance,
            weight=weight,
            description=data.get('description', ''),
            user_id=data.get('user_id', 1),  # Default user_id for testing
            cost=cost,
            delivery_speed=data['delivery_speed'],
            status='Pending'  # Default status
        )
        db.session.add(parcel)
        db.session.commit()

        return jsonify({
            'message': 'Parcel created successfully',
            'parcel': parcel.to_dict()
        }), 201
    except Exception as e:
        print(f"Error creating parcel: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/parcels/<int:parcel_id>', methods=['GET'])
def get_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    return jsonify(parcel.to_dict())

@app.route('/parcels/<int:parcel_id>', methods=['PATCH'])
def update_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    data = request.get_json()
    if 'status' in data:
        parcel.status = data['status']
    if 'current_location' in data:
        parcel.current_location = data['current_location']
    db.session.commit()
    return jsonify(parcel.to_dict())

@app.route('/parcels/<int:parcel_id>', methods=['DELETE'])
def delete_parcel(parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    db.session.delete(parcel)
    db.session.commit()
    return '', 204

@app.route('/stats', methods=['GET'])
@token_required(roles=['admin'])
def get_stats(current_user):
    total_deliveries = Parcel.query.count()
    pending_orders = Parcel.query.filter_by(status='Pending').count()
    in_transit_orders = Parcel.query.filter_by(status='In Transit').count()
    delivered_orders = Parcel.query.filter_by(status='Delivered').count()

    return jsonify({
        'total_deliveries': total_deliveries,
        'pending_orders': pending_orders,
        'in_transit_orders': in_transit_orders,
        'delivered_orders': delivered_orders
    })

# New Endpoint: Get User Details
@app.route('/user', methods=['GET'])
# @token_required()  # Temporarily commenting out the token_required decorator
def get_user():
    try:
        # For testing purposes, hardcode a user_id or fetch the first user
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

# New Endpoint: Update User Settings
@app.route('/settings', methods=['POST'])
# @token_required()  # Temporarily commenting out the token_required decorator
def update_settings():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # For testing purposes, hardcode a user_id or fetch the first user
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

@app.route('/parcels/<int:parcel_id>/cancel', methods=['POST'])
# @token_required()
def cancel_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to cancel this parcel")

    if parcel.status == 'Cancelled':
        return jsonify({'error': 'This parcel is already cancelled'}), 400

    data = request.get_json()
    if not data or not data.get('cancel_reason'):
        return jsonify({'error': 'Cancellation reason is required'}), 400

    parcel.status = 'Cancelled'
    parcel.cancel_date = datetime.utcnow()
    parcel.cancel_reason = data['cancel_reason']
    parcel.refund_status = 'Pending'  

    db.session.commit()

    return jsonify({
        'message': 'Parcel cancelled successfully',
        'parcel': parcel.to_dict()
    }), 200

@app.route('/parcels/cancelled', methods=['GET'])
# @token_required()  # Ensure this decorator is applied
def get_cancelled_parcels(current_user):
    try:
        if current_user.role == 'admin':
            # Admin can see all cancelled parcels
            cancelled_parcels = Parcel.query.filter_by(status='Cancelled').all()
        else:
            # Regular users can only see their own cancelled parcels
            cancelled_parcels = Parcel.query.filter_by(user_id=current_user.id, status='Cancelled').all()

        # Convert parcels to a list of dictionaries
        parcels_data = [parcel.to_dict() for parcel in cancelled_parcels]
        return jsonify(parcels_data), 200
    except Exception as e:
        print(f"Error fetching cancelled parcels: {e}")
        return jsonify({'error': 'Failed to fetch cancelled parcels'}), 500

@app.route('/user/items', methods=['GET'])
# @token_required()  
def get_user_items():
    try:
        user_id = 1  # Replace with a valid user_id for testing
        items = Item.query.filter_by(user_id=user_id).all()

        items_data = [item.to_dict() for item in items]

        return jsonify(items_data), 200
    except Exception as e:
        print(f"Error fetching user items: {e}")
        return jsonify({'error': 'Failed to fetch user items'}), 500

if __name__ == '__main__':
    app.run(debug=True)