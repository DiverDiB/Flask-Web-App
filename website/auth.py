from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_required, logout_user, current_user, login_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    email=None
    password=None
    if request.method == 'POST':
        data = request.form
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
                
            else:
                flash("Incorrect password.", category='error')
        else:
            flash("User not found.", category='error')
        
    return render_template("login.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out. See you soon!", category='success')
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    email=None
    firstName=None
    if request.method == 'POST':
        data = request.form
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash("User already exists.", category='error')
        elif len(email) < 10:
            flash("Email must be at least 10 characters.", category='error')
        elif len(firstName) < 2:
            email=email
            flash("First name must be at least 2 characters.", category='error')
        elif len(password1) < 8:
            firstName=firstName
            flash("Password must be at least 8 characters.", category='error')
        elif (password1 != password2):
            flash("Passwords do not match.", category='error')
        else:
            new_user = User(email=email, first_name=firstName, password=generate_password_hash(password1, method='scrypt', salt_length=16))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!", category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('views.home'))
            
    return render_template("sign_up.html", user=current_user)
