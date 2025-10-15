from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from app import app
from models import db, User, Doctor, Patient, Appointment, Department, Treatment
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy.exc import SQLAlchemyError
from datetime import datetime
from sqlalchemy import and_
import os

# -------------------- DECORATORS --------------------
def auth_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return inner

def admin_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to continue', 'warning')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if user.role != 'admin':
            flash('You are not authorized to view this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return inner

# -------------------- INDEX & AUTH --------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('auth/login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if not username or not password:
        flash('Username and password cannot be empty', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

    if not user.check_password(password):
        flash('Incorrect password', 'danger')
        return redirect(url_for('login'))

    # Login successful
    session['user_id'] = user.id
    flash('Login successful', 'success')

    # Redirect based on role
    if user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    elif user.role == 'doctor':
        return redirect(url_for('doctor_dashboard'))
    else:
        return redirect(url_for('patient_dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logout successful', 'info')
    return redirect(url_for('login'))

# -------------------- REGISTER --------------------
@app.route('/register')
def register():
    departments = Department.query.all()
    return render_template('auth/register.html', departments=departments)

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    name = request.form.get('name')
    email = request.form.get('email')
    role = request.form.get('role')

    # Validation checks
    if not username or not password or not confirm_password or not name:
        flash('Please fill all required fields', 'danger')
        return redirect(url_for('register'))

    if password != confirm_password:
        flash('Passwords do not match', 'danger')
        return redirect(url_for('register'))

    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash('Username already exists', 'danger')
        return redirect(url_for('register'))

    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        flash('Email already exists', 'danger')
        return redirect(url_for('register'))

    # Create new user
    new_user = User(
        username=username,
        passhash=generate_password_hash(password),
        name=name,
        email=email,
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    # Additional details based on role
    if role == 'doctor':
        dept_id = request.form.get('department_id')
        specialization = request.form.get('specialization')
        qualification = request.form.get('qualification')
        phone = request.form.get('phone')

        if not dept_id:
            flash("Please select a department", "danger")
            return redirect(url_for('register'))

        doctor = Doctor(
            user_id=new_user.id,
            department_id=int(dept_id),
            specialization=specialization,
            qualification=qualification,
            phone=phone
        )
        db.session.add(doctor)
        db.session.commit()
        flash("Doctor account created successfully!", "success")
        return redirect(url_for('login'))

    elif role == 'patient':
        address = request.form.get('address')
        phone = request.form.get('phone')
        blood_group = request.form.get('blood_group')
        emergency_contact = request.form.get('emergency_contact')

        patient = Patient(
            user_id=new_user.id,
            address=address,
            phone=phone,
            blood_group=blood_group,
            emergency_contact=emergency_contact
        )
        db.session.add(patient)
        db.session.commit()
        flash("Patient account created successfully!", "success")
        return redirect(url_for('login'))

    else:
        flash("Invalid role selected", "danger")
        return redirect(url_for('register'))

# -------------------- DASHBOARD ROUTES (DUMMY FOR NOW) --------------------
@app.route('/admin/dashboard')
@auth_required
@admin_required
def admin_dashboard():
    return render_template('dashboards/admin_dashboard.html')

@app.route('/doctor/dashboard')
@auth_required
def doctor_dashboard():
    user = User.query.get(session['user_id'])
    if user.role != 'doctor':
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    return render_template('dashboards/doctor_dashboard.html')

@app.route('/patient/dashboard')
@auth_required
def patient_dashboard():
    user = User.query.get(session['user_id'])
    if user.role != 'patient':
        flash("Access denied", "danger")
        return redirect(url_for('index'))
    return render_template('dashboards/patient_dashboard.html')
