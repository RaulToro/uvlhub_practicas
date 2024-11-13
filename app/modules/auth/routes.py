from flask import render_template, redirect, url_for, request
from flask_login import current_user, login_user, logout_user

from app.modules.auth import auth_bp
from app.modules.auth.forms import SignupForm, LoginForm, EmailValidationForm
from app.modules.auth.services import AuthenticationService
from app.modules.profile.services import UserProfileService
import random

authentication_service = AuthenticationService()
user_profile_service = UserProfileService()


@auth_bp.route("/signup/", methods=["GET", "POST"])
def show_signup_form():
    if current_user.is_authenticated:
        return redirect(url_for('public.index'))

    form = SignupForm()
    if form.validate_on_submit():
        email = form.email.data
        if not authentication_service.is_email_available(email):
            return render_template("auth/signup_form.html", form=form, error=f'Email {email} in use')

        try:
            user = authentication_service.create_with_profile(**form.data)
        except Exception as exc:
            return render_template("auth/signup_form.html", form=form, error=f'Error creating user: {exc}')

        # Log user
        login_user(user, remember=True)
        return redirect(url_for('auth.email_validation'))

    return render_template("auth/signup_form.html", form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('public.index'))

    form = LoginForm()
    if request.method == 'POST' and form.validate_on_submit():
        if authentication_service.correct_credentials(form.email.data, form.password.data):
            return redirect(url_for('auth.email_validation'))

        return render_template("auth/login_form.html", form=form, error='Invalid credentials')

    return render_template('auth/login_form.html', form=form)


@auth_bp.route('/email_validation', methods=['GET', 'POST'])
def email_validation():
    if current_user.is_authenticated:
        return redirect(url_for('public.index'))

    # Creation of the key
    random_key = random.randint(100000, 999999)
    # TODO Add the actual customer email
    target_email = 'customer@gmail.com'
    authentication_service.send_email(target_email, random_key)
    # Actual validation
    form = EmailValidationForm()
    if request.method == 'POST' and form.validate_on_submit():
        if form.key.data == random_key:
            if authentication_service.login(form.email.data, form.password.data):
                return redirect(url_for('public.index'))

        return render_template("auth.email_validation_form.html", form=form, error='The key does not match')

    return render_template('auth/email_validation_form.html', form=form)


@auth_bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('public.index'))
