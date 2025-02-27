import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or '87f0472af5773b86bb52188afa26d7885862d752b60ba7c9'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://parcel_postgres_user:LhJhhPca6zWenReZeaEUIcYm2arA9pZK@dpg-cv062cogph6c73c7ou00-a.oregon-postgres.render.com/parcel_postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GOOGLE_MAPS_API_KEY = os.environ.get('GOOGLE_MAPS_API_KEY') or 'AIzaSyBMSIhZT1MzTsQ3EN-ys3RmndgFO3ygU4w'