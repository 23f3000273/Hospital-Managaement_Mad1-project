from app import app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy(app)

# -------------------- MODELS --------------------

class Department(db.Model):
    __tablename__ = 'department'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256), nullable=True)

    # One department can have many doctors
    doctors = db.relationship('Doctor', backref='department', lazy=True)

class User(db.Model):
    """
    Base table for all users (Admin staff, Doctors, Patients).
    We'll distinguish by role.
    """
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    passhash = db.Column(db.String(256), nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=True)
    name = db.Column(db.String(64), nullable=False)
    role = db.Column(db.String(16), nullable=False, default='patient')  
    # role choices: 'admin', 'doctor', 'patient'

    # Relationships
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False)
    patient_profile = db.relationship('Patient', backref='user', uselist=False)

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.passhash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.passhash, password)


class Doctor(db.Model):
    __tablename__ = 'doctor'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=False)
    specialization = db.Column(db.String(128), nullable=True)
    qualification = db.Column(db.String(128), nullable=True)
    phone = db.Column(db.String(32), nullable=True)

    appointments = db.relationship('Appointment', backref='doctor', lazy=True)


class Patient(db.Model):
    __tablename__ = 'patient'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    address = db.Column(db.String(256), nullable=True)
    phone = db.Column(db.String(32), nullable=True)
    blood_group = db.Column(db.String(8), nullable=True)
    emergency_contact = db.Column(db.String(64), nullable=True)

    appointments = db.relationship('Appointment', backref='patient', lazy=True)


class Appointment(db.Model):
    __tablename__ = 'appointment'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctor.id'), nullable=False)

    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Booked')  
    # choices: Booked / Completed / Cancelled
    reason = db.Column(db.String(256), nullable=True)

    treatment = db.relationship('Treatment', backref='appointment', uselist=False, lazy=True)


class Treatment(db.Model):
    __tablename__ = 'treatment'
    id = db.Column(db.Integer, primary_key=True)
    appointment_id = db.Column(db.Integer, db.ForeignKey('appointment.id'), nullable=False)
    diagnosis = db.Column(db.String(512), nullable=True)
    prescription = db.Column(db.String(512), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    follow_up_date = db.Column(db.Date, nullable=True)

# -------------------- INITIALIZATION --------------------
with app.app_context():
    db.create_all()

    # Ensure at least one Admin user exists
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        admin = User(
            username='admin',
            name='Hospital Admin',
            email='admin@hospital.com',
            role='admin'
        )
        admin.password = 'admin'  # triggers hashing via the setter
        db.session.add(admin)
        db.session.commit()
