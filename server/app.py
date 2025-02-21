from flask import Flask, request, jsonify, abort
from flask_migrate import Migrate
from flask_cors import CORS
from config import Config
from models import db, User, Parcel
from functools import wraps
import jwt
import datetime
import requests  # For Google Maps API requests

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
CORS(app)

# Helper function for JWT authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            abort(401, description="Token is missing!")
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.get(data['user_id'])
        except:
            abort(401, description="Token is invalid!")
        return f(current_user, *args, **kwargs)
    return decorated

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
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'])
        return jsonify({'token': token})
    abort(401, description="Invalid username or password")

@app.route('/parcels', methods=['GET'])
@token_required
def get_parcels(current_user):
    if current_user.role == 'admin':
        parcels = Parcel.query.all()
    else:
        parcels = Parcel.query.filter_by(user_id=current_user.id).all()
    return jsonify([parcel.to_dict() for parcel in parcels])

@app.route('/parcels', methods=['POST'])
@token_required
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
        cost=cost  # Add cost to the parcel
    )
    db.session.add(parcel)
    db.session.commit()
    return jsonify(parcel.to_dict()), 201

@app.route('/parcels/<int:parcel_id>', methods=['GET'])
@token_required
def get_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to view this parcel")
    return jsonify(parcel.to_dict())

@app.route('/parcels/<int:parcel_id>', methods=['PATCH'])
@token_required
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
@token_required
def delete_parcel(current_user, parcel_id):
    parcel = Parcel.query.get_or_404(parcel_id)
    if current_user.role != 'admin' and parcel.user_id != current_user.id:
        abort(403, description="You do not have permission to delete this parcel")
    db.session.delete(parcel)
    db.session.commit()
    return '', 204

if __name__ == '__main__':
    app.run(debug=True)