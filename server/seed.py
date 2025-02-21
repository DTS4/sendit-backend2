from app import app, db
from models import User, Parcel

def seed_data():
    with app.app_context():
        db.drop_all()
        db.create_all()

        # Create users
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')
        user1 = User(username='user1', email='user1@example.com')
        user1.set_password('user123')

        db.session.add(admin)
        db.session.add(user1)
        db.session.commit()

        # Create parcels
        parcel1 = Parcel(
            tracking_id='TRK123',
            pickup_location='New York',
            destination='Los Angeles',
            weight=5.0,
            description='Fragile items',
            user_id=user1.id,
            cost=150.0  
        )
        parcel2 = Parcel(
            tracking_id='TRK456',
            pickup_location='San Francisco',
            destination='Chicago',
            weight=10.0,
            description='Electronics',
            user_id=user1.id,
            cost=300.0  
        )
        db.session.add(parcel1)
        db.session.add(parcel2)
        db.session.commit()

if __name__ == '__main__':
    seed_data()