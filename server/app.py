from flask import Flask, request, jsonify, abort, redirect
from flask_migrate import Migrate
from flask_cors import CORS
from flask_mail import Mail, Message
from server.config import Config 
from server.models import db, User, Parcel, Item
from functools import wraps
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import bcrypt
import jwt
import datetime
import random
import string
import requests

app = Flask(__name__)
app.config.from_object(Config)

secret_key = app.config['SECRET_KEY']
s = URLSafeTimedSerializer(secret_key, salt="password-reset")
email = "keithgithinji@gmail.com"  
token = s.dumps(email, salt="password-reset")

app.config['MAIL_SERVER'] = "smtp.gmail.com"  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True  
app.config['MAIL_USERNAME'] = "keithgithinji@gmail.com"  
app.config['MAIL_PASSWORD'] = "uwor rjoa pcwb taiy"  
app.config['MAIL_DEFAULT_SENDER'] = "keithgithinji@gmail.com"  

mail = Mail(app)

db.init_app(app)
migrate = Migrate(app, db)

CORS(app, resources={r"/*": {"origins": "*"}})

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
        return round(distance_km, 2) 

    except Exception as e:
        print(f"Error calculating distance: {e}")
        return None

# Function to generate reset token
def generate_reset_token(length=32):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

# Function to send email
def send_email(subject, recipient, body):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
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

        # Validate required fields
        if not all([data.get('username'), data.get('email'), data.get('password'), data.get('confirm_password')]):
            return jsonify({'error': 'All fields (username, email, password, confirm_password) are required.'}), 400

        # Check if passwords match
        if data['password'] != data['confirm_password']:
            return jsonify({'error': 'Passwords do not match.'}), 400

        # Check if username already exists
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'error': 'Username already exists.'}), 400

        # Check if email already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already exists.'}), 400

        try:
            # Create new user
            user = User(
                username=data['username'],
                email=data['email'],
                role=data.get('role', 'user')  # Default role to 'user'
            )
            user.set_password(data['password'])  # Set hashed password
            db.session.add(user)
            db.session.commit()

            return jsonify({
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role 
                }
            }), 201

        except Exception as e:
            print(f"Error during signup: {e}")
            db.session.rollback() 
            return jsonify({'error': 'Internal server error'}), 500

    elif request.method == 'GET':
        return jsonify({'message': 'Signup endpoint. Use POST to create a new user.'}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    print(f"Received forgot-password request: {data}") 

    if not data.get('email'):
        return jsonify({'error': 'Email is required'}), 400

    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 400

    try:
        reset_token = s.dumps(user.email, salt="password-reset")
        print(f"Generated reset token: {reset_token}")  
    except Exception as e:
        print(f"Error generating reset token: {e}")
        return jsonify({'error': 'Failed to generate reset token'}), 500

    reset_link = f"http://localhost:3000/reset-password/{reset_token}"
    subject = "Password Reset Request"
    body = f"Click the link to reset your password: {reset_link}"

    print(f"Generated reset link: {reset_link}")  
    try:
        msg = Message(subject, recipients=[user.email])
        msg.body = body
        mail.send(msg)
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        print(f"Failed to send email: {e}")
        return jsonify({'error': 'Failed to send email'}), 500

@app.route("/reset-password/<token>", methods=["GET", "POST", "OPTIONS"])
def reset_password(token):
    print(f"Received {request.method} request to /reset-password/{token}")  # Debugging

    # Handle OPTIONS preflight request (for CORS)
    if request.method == "OPTIONS":
        return "", 204

    # Redirect GET requests to frontend reset page
    if request.method == "GET":
        frontend_url = f"http://localhost:3000/reset-password/{token}"  # Update with your frontend URL
        return redirect(frontend_url)

    # Handle password reset on POST request
    if request.method == "POST":
        try:
            # Verify the token
            email = s.loads(token, salt="password-reset", max_age=1800)  # Token expires in 30 minutes
        except (SignatureExpired, BadTimeSignature):
            return jsonify({"error": "Invalid or expired token"}), 400

        data = request.get_json()
        if not data or "password" not in data:
            return jsonify({"error": "Password is required"}), 400

        new_password = data["password"]

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Update and hash password
        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        db.session.commit()

        return jsonify({"message": "Password successfully reset."}), 200
    
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

        send_email(user.email, email_subject, email_content)

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
@app.route('/parcels/<int:parcel_id>/update_status', methods=['POST'], endpoint='update_parcel_status')
def update_parcel_status(parcel_id):
    try:
        parcel = Parcel.query.get_or_404(parcel_id)

        data = request.get_json()
        if not data or 'status' not in data:
            return jsonify({'error': 'Status field is required'}), 400

        # Normalize the incoming status value
        new_status = data['status'].strip().replace('-', ' ').capitalize()

        valid_statuses = ['Pending', 'In-Transit', 'Delivered']
        if new_status not in valid_statuses:
            return jsonify({'error': 'Invalid status'}), 400

        if parcel.status == 'Delivered':
            return jsonify({'error': 'You cannot update the status of a delivered parcel'}), 400

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
@app.route('/parcels/<int:parcel_id>', methods=['PATCH'], endpoint='patch_parcel')
def patch_parcel(parcel_id):
    try:
        # Fetch the parcel by ID
        parcel = Parcel.query.get_or_404(parcel_id)

        # Check if the parcel has already been delivered
        if parcel.status == 'Delivered':
            return jsonify({'error': 'You cannot update a delivered parcel'}), 400

        # Get the JSON data from the request
        data = request.get_json()

        # Update the destination if provided
        if 'destination' in data:
            new_destination = data['destination']
            old_destination = parcel.destination

            # Recalculate distance if the destination is updated
            if new_destination != old_destination:
                distance = calculate_osrm_distance(parcel.pickup_location, new_destination)
                if distance is None:
                    return jsonify({'error': 'Failed to calculate new distance'}), 400

                # Recalculate cost based on the new distance
                try:
                    weight = float(parcel.weight)
                    cost = calculate_cost(distance, weight)
                except (ValueError, TypeError):
                    return jsonify({'error': 'Invalid weight or distance value'}), 400

                # Update the parcel's attributes
                parcel.distance = distance
                parcel.cost = cost
                parcel.destination = new_destination

        # Update the current location if provided
        if 'current_location' in data:
            parcel.current_location = data['current_location']

        # Commit changes to the database
        db.session.commit()

        return jsonify({
            'message': 'Parcel updated successfully',
            'parcel': parcel.to_dict()
        }), 200

    except Exception as e:
        print(f"Error updating parcel: {e}")
        return jsonify({'error': 'Failed to update parcel'}), 500

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
        in_transit_orders = Parcel.query.filter_by(status='In-Transit').count()
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
@app.route('/api/user', methods=['GET'], endpoint='get_user_v2') 
# @token_required()
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

@app.route('/contact-us', methods=['POST'])
def contact_us():
    data = request.get_json()
    if not all([data.get('name'), data.get('email'), data.get('message')]):
        return jsonify({'error': 'All fields (name, email, message) are required.'}), 400

    name = data['name']
    email = data['email']
    message = data['message']

    subject = f"New Contact Form Submission from {name}"
    body = f"Name: {name}\nEmail: {email}\nMessage: {message}"

    try:
        msg = Message(subject, recipients=[os.getenv("EMAIL_ADDRESS")])
        msg.body = body
        mail.send(msg)
        return jsonify({'message': 'Your message has been sent successfully!'}), 200
    except Exception as e:
        print(f"Failed to send email: {e}")
        return jsonify({'error': 'Failed to send your message.'}), 500

if __name__ == '__main__':
    app.run(debug=True)