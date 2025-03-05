# SendIt - Parcel Delivery Management System

SendIt is a full-stack web application designed to manage parcel deliveries efficiently. It provides features for users to create, track, and manage parcels, while admins can update parcel statuses and view delivery statistics.

---

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Endpoints](#api-endpoints)
- [Frontend Integration](#frontend-integration)
- [Running the Application](#running-the-application)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### User Features
- **User Authentication**: Register, login, and logout functionality.
- **Parcel Creation**: Users can create new parcel delivery orders.
- **Parcel Tracking**: Users can track the status of their parcels.
- **Password Reset**: Users can reset their passwords via email.

### Admin Features
- **Parcel Management**: Admins can update parcel statuses (Pending, In Transit, Delivered).
- **Delivery Statistics**: Admins can view delivery statistics (e.g., total deliveries, pending orders, etc.).
- **User Management**: Admins can view user details and manage user roles.

---

## Technologies Used

### Backend
- **Python**: Primary programming language.
- **Flask**: Web framework for building the backend API.
- **SQLAlchemy**: ORM for database management.
- **PostgreSQL**: Relational database for storing application data.
- **JWT**: JSON Web Tokens for user authentication.
- **Flask-Mail**: For sending emails (e.g., password reset).

### Frontend
- **React**: JavaScript library for building the user interface.
- **Axios**: For making HTTP requests to the backend API.
- **React Router**: For handling client-side routing.

### Other Tools
- **Render**: For deploying the backend.
- **Vercel**: For deploying the frontend.
- **Git**: Version control system.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- PostgreSQL
- Node.js (for frontend development)

### Backend Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/sendit-backend.git
   cd sendit-backend

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install dependencies:
   ```bash
   pip install -r requirements.txt

4. Set up the database:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade

5. Run the backend server:
   ```bash
   flask run

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd ../sendit-frontend

2. Install dependencies:
   ```bash
   npm install

3. Start the development server:
   ```bash
   npm start

## Configuration
### Backend Configuration

- Create a .env file in the root directory of the backend with the following variables:

   ```env
   SECRET_KEY=your-secret-key
   DATABASE_URI=postgresql://username:password@localhost:5432/sendit
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-email-password

### Frontend configuration

- Create a .env file in the root directory of the frontend with the following variables:

   ```env
   REACT_APP_API_URL=http://localhost:5000

## API Endpoints
### Authentication

* POST /login: User login.
* POST /signup: User registration.
* POST /forgot-password: Request password reset.
* POST /reset-password/<token>: Reset password.

### Parcel Management

* GET /parcels: Fetch all parcels.
* POST /parcels: Create a new parcel.
* POST /parcels/int:parcel_id/update_status: Update parcel status (Admin only).
* POST /parcels/int:parcel_id/cancel: Cancel a parcel.
* GET /parcels/cancelled: Fetch cancelled parcels.

#### Statistics
* GET /stats: Fetch delivery statistics.

## Contributing
Contributions are welcome! Follow these steps to contribute:

1. Fork the repository.

2. Create a new branch:
   ```bash
   git checkout -b feature/your-feature-name

3. Commit your changes:
   ```bash
   git commit -m "Add your feature"

4. Push to the branch:
   ```bash
   git push origin feature/your-feature-name

5. Open a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments
* Special thanks to all contributors and open-source libraries used in this project.




