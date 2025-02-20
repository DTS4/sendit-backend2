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
            user_id=user1.id
        )
        db.session.add(parcel1)
        db.session.commit()

if __name__ == '__main__':
    seed_data()