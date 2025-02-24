from flask import Flask, request, jsonify, abort
from flask_migrate import Migrate
from flask_cors import CORS
from server.config import Config
from models import db, User, Parcel
from functools import wraps
import jwt
import datetime
import requests  

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)

# Helper function for JWT authentication with role-based access control
def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization')
            if not token:
                abort(401, description="Token is missing!")
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = User.query.get(data['user_id'])
                if roles and current_user.role not in roles:
                    abort(403, description="You do not have permission to access this resource.")
            except:
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

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'role': user.role,  # Include role in the token
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token, 'role': user.role})  # Return role in the response
    abort(401, description="Invalid username or password")

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Validate required fields
    if not data.get('username') or not data.get('email') or not data.get('password'):
        abort(400, description="Username, email, and password are required.")

    # Check if username or email already exists
    if User.query.filter_by(username=data['username']).first():
        abort(400, description="Username already exists.")
    if User.query.filter_by(email=data['email']).first():
        abort(400, description="Email already exists.")

    # Create a new user
    user = User(
        username=data['username'],
        email=data['email'],
        role=data.get('role', 'user')  # Default role is 'user'
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'role': user.role
    }), 201

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

if __name__ == '__main__':
    app.run()