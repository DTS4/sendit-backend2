import sys
import os

# Ensure the script can find the server module
if __package__ is None:
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.app import app, db
from server.models import User, Parcel, Item
from datetime import datetime

def seed_data():
    with app.app_context():
        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()

        # Create admin user
        admin = User(username='admin', email='admin@example.com', role='admin')
        admin.set_password('admin123')

        # Create regular users
        user1 = User(username='user1', email='user1@example.com', role='user')
        user1.set_password('user123')

        user2 = User(username='user2', email='user2@example.com', role='user')
        user2.set_password('user123')

        db.session.add(admin)
        db.session.add(user1)
        db.session.add(user2)
        db.session.commit()

        # Create parcels
        parcel1 = Parcel(
            tracking_id='TRK123',
            pickup_location='New York',
            destination='Los Angeles',
            distance=2800,  # Distance in kilometers
            weight=5.0,
            description='Fragile items',
            user_id=user1.id,
            cost=150.0,
            delivery_speed='Standard',
            status='Pending'
        )
        parcel2 = Parcel(
            tracking_id='TRK456',
            pickup_location='San Francisco',
            destination='Chicago',
            distance=3400,  # Distance in kilometers
            weight=10.0,
            description='Electronics',
            user_id=user1.id,
            cost=300.0,
            delivery_speed='Express',
            status='In Transit'
        )
        parcel3 = Parcel(
            tracking_id='TRK789',
            pickup_location='Miami',
            destination='Seattle',
            distance=4500,  # Distance in kilometers
            weight=7.5,
            description='Clothing',
            user_id=user2.id,
            cost=225.0,
            delivery_speed='Standard',
            status='Delivered'
        )
        db.session.add(parcel1)
        db.session.add(parcel2)
        db.session.add(parcel3)
        db.session.commit()

        # Create items
        item1 = Item(
            name='Smartphone',
            image_url='https://res.cloudinary.com/dulnfomcr/image/upload/v1740939663/4171_tmndus.jpg',
            rating=4.5,
            price=599.99,
            purchase_date=datetime.utcnow(),
            user_id=user1.id
        )
        item2 = Item(
            name='Laptop',
            image_url='https://res.cloudinary.com/dulnfomcr/image/upload/v1740939754/61LdecwlWYL_bk62iu.jpg',
            rating=4.7,
            price=1299.99,
            purchase_date=datetime.utcnow(),
            user_id=user1.id
        )
        item3 = Item(
            name='Headphones',
            image_url='https://res.cloudinary.com/dulnfomcr/image/upload/v1740939705/MQTQ3_vh4mmp.jpg',
            rating=4.2,
            price=199.99,
            purchase_date=datetime.utcnow(),
            user_id=user2.id
        )
        item4 = Item(
            name='Smartwatch',
            image_url='https://res.cloudinary.com/dulnfomcr/image/upload/v1740939969/71pbEc1KO3L_ypysfv.jpg',
            rating=4.0,
            price=299.99,
            purchase_date=datetime.utcnow(),
            user_id=user2.id
        )
        db.session.add(item1)
        db.session.add(item2)
        db.session.add(item3)
        db.session.add(item4)
        db.session.commit()

        print("Database seeded successfully!")

if __name__ == '__main__':
    seed_data()