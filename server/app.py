from flask import Flask, request, jsonify, abort
from flask_migrate import Migrate
from flask_cors import CORS
from server.config import Config
from server.models import db, User, Parcel
from functools import wraps
import jwt
import datetime
import requests
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)

# Flask-Mail configuration for Mailtrap
app.config['MAIL_SERVER'] = 'live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'apismtp@mailtrap.io'  # Updated username
app.config['MAIL_PASSWORD'] = 'a8769ffcd097e16768a3457f55ca653b'  # Your Mailtrap password
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

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

# Helper function to calculate cost using Google Maps Distance Matrix API
def calculate_cost(pickup, destination, weight):
    url = f"https://maps.googleapis.com/maps/api/distancematrix/json?units=metric&origins={pickup}&destinations={destination}&key={app.config['GOOGLE_MAPS_API_KEY']}"
    response = requests.get(url)
    data = response.json()

    if data['status'] != 'OK':
        return None

    distance = data['rows'][0]['elements'][0]['distance']['value']  # Distance in meters
    cost = (distance / 1000) * 1.5 * weight  # $1.5 per km per kg
    return round(cost, 2)

# Routes
@app.route('/')
def home():
    return "Parcel Delivery Backend"

@app.route('/send-email')
def send_email():
    try:
        msg = Message(
            subject='Hello from Flask-Mail!',
            sender='no-reply@mailtrap.io',  # Use a Mailtrap-allowed domain
            recipients=['recipient@example.com']
        )
        msg.body = 'This is a test email sent from Flask-Mail using Mailtrap.'
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return f"Failed to send email: {str(e)}"

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

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        # Return a simple HTML form for testing
        return '''
            <form method="post">
                <label for="fullName">Full Name:</label>
                <input type="text" id="fullName" name="fullName"><br>
                <label for="email">Email:</label>
                <input type="email" id="email" name="email"><br>
                <button type="submit">Send Reset Link</button>
            </form>
        '''
    elif request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        full_name = data.get('fullName')  # Ensure this matches the frontend payload

        # Validate required fields
        if not email or not full_name:
            return jsonify({
                'error': 'Email and full name are required.'
            }), 400

        # Check if the user exists
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({
                'error': 'User not found.'
            }), 404

        try:
            # Generate a reset token
            reset_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'])

            # Send reset email
            msg = Message(
                subject='Password Reset Request',
                sender='no-reply@mailtrap.io',  # Use a Mailtrap-allowed domain
                recipients=[user.email]
            )
            msg.body = f'''Hello {full_name},

To reset your password, visit the following link:
{request.host_url}reset-password/{reset_token}

If you did not make this request, please ignore this email.
'''
            mail.send(msg)

            return jsonify({
                'message': 'Password reset email sent.'
            }), 200
        except Exception as e:
            print(f"Error sending email: {e}")
            return jsonify({
                'error': 'Failed to send reset email. Please try again.'
            }), 500

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        # Return a simple HTML form for testing
        return '''
            <form method="post">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email"><br>
                <button type="submit">Reset Password</button>
            </form>
        '''
    elif request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        user = User.query.filter_by(email=email).first()
        if not user:
            abort(404, description="User not found.")

        try:
            # Generate a reset token
            reset_token = jwt.encode({
                'user_id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config['SECRET_KEY'])

            # Send reset email
            msg = Message(
                subject='Password Reset Request',
                sender='no-reply@mailtrap.io',  # Use a Mailtrap-allowed domain
                recipients=[user.email]
            )
            msg.body = f'''To reset your password, visit the following link:
{request.host_url}reset-password/{reset_token}

If you did not make this request, please ignore this email.
'''
            mail.send(msg)

            return jsonify({'message': 'Password reset email sent'}), 200
        except Exception as e:
            print(f"Error sending email: {e}")
            return jsonify({
                'error': 'Failed to send reset email. Please try again.'
            }), 500

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_confirm(token):
    if request.method == 'GET':
        # Return a simple HTML form for testing
        return '''
            <form method="post">
                <label for="new_password">New Password:</label>
                <input type="password" id="new_password" name="new_password"><br>
                <label for="confirm_password">Confirm Password:</label>
                <input type="password" id="confirm_password" name="confirm_password"><br>
                <button type="submit">Reset Password</button>
            </form>
        '''
    elif request.method == 'POST':
        data = request.get_json()
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        # Validate required fields
        if not new_password or not confirm_password:
            return jsonify({
                'error': 'New password and confirm password are required.'
            }), 400

        # Check if passwords match
        if new_password != confirm_password:
            return jsonify({
                'error': 'Passwords do not match.'
            }), 400

        try:
            # Decode the token to get the user ID
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['user_id'])
            if not user:
                return jsonify({
                    'error': 'User not found.'
                }), 404

            # Update the user's password
            user.set_password(new_password)
            db.session.commit()

            return jsonify({
                'message': 'Password reset successfully.'
            }), 200
        except jwt.ExpiredSignatureError:
            return jsonify({
                'error': 'Token has expired.'
            }), 400
        except jwt.InvalidTokenError:
            return jsonify({
                'error': 'Invalid or expired token.'
            }), 400
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({
                'error': 'Something went wrong. Please try again.'
            }), 500

@app.route('/parcels', methods=['GET'])
@token_required()
def get_parcels(current_user):
    status = request.args.get('status')
    user_id = request.args.get('user_id')

    query = Parcel.query
    if current_user.role != 'admin':
        query = query.filter_by(user_id=current_user.id)
    if status:
        query = query.filter_by(status=status)
    if user_id and current_user.role == 'admin':
        query = query.filter_by(user_id=user_id)

    parcels = query.all()
    return jsonify([parcel.to_dict() for parcel in parcels])

@app.route('/parcels', methods=['POST'])
@token_required()
def create_parcel(current_user):
    data = request.get_json()
    cost = calculate_cost(data['pickup_location'], data['destination'], data['weight'])
    if cost is None:
        abort(400, description="Failed to calculate cost. Check pickup and destination locations.")

    parcel = Parcel(
        tracking_id=data['tracking_id'],
        pickup_location=data['pickup_location'],
        destination=data['destination'],
        weight=data['weight'],
        description=data.get('description', ''),
        user_id=current_user.id,
        cost=cost,
        delivery_speed=data.get('delivery_speed')  # Added delivery speed
    )
    db.session.add(parcel)
    db.session.commit()
    return jsonify(parcel.to_dict()), 201

@app.route('/parcels/<int:parcel_id>', methods=['GET'])
@token_required()
def get_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to view this parcel")
    return jsonify(parcel.to_dict())

@app.route('/parcels/<int:parcel_id>', methods=['PATCH'])
@token_required()
def update_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to update this parcel")
    data = request.get_json()
    if 'status' in data:
        parcel.status = data['status']
    if 'current_location' in data:
        parcel.current_location = data['current_location']
    db.session.commit()
    return jsonify(parcel.to_dict())

@app.route('/parcels/<int:parcel_id>', methods=['DELETE'])
@token_required()
def delete_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to delete this parcel")
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
@token_required()
def get_user(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role
    })

# New Endpoint: Update User Settings
@app.route('/settings', methods=['POST'])
@token_required()
def update_settings(current_user):
    data = request.get_json()
    if not data:
        abort(400, description="No data provided.")

    if 'email_notifications' in data:
        current_user.email_notifications = data['email_notifications']
    if 'dark_mode' in data:
        current_user.dark_mode = data['dark_mode']

    db.session.commit()
    return jsonify({'message': 'Settings updated successfully'}), 200

if __name__ == '__main__':
    app.run(debug=True)