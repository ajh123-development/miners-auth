from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from ..database import db
from .. import database
from ..models.account import User, Client, Grant, Token


auth_blueprint = Blueprint('auth', __name__)

@auth_blueprint.route('/login')
def login():
    return render_template('login.html', user=current_user)

@auth_blueprint.route('/login', methods=['POST'])
def login_post():
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    user.authenticated = True
    db.session.commit()
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))

@auth_blueprint.route('/signup')
def signup():
    return render_template('signup.html', user=current_user)

@auth_blueprint.route('/signup', methods=['POST'])
def signup_post():
    # code to validate and add user to database goes here
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'), authenticated=False)

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('auth.login'))

@auth_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    current_user.authenticated = False
    db.session.commit()
    return redirect(url_for('main.index'))

@auth_blueprint.route('/authorise', methods=['GET', 'POST'])
@database.oauth.authorize_handler
@login_required
def authorize(*args, **kwargs):
    # NOTICE: for real project, you need to require login
    if request.method == 'GET':
        # render a page for user to confirm the authorization
        return render_template('authorise.html', user=current_user)

    if request.method == 'HEAD':
        # if HEAD is supported properly, request parameters like
        # client_id should be validated the same way as for 'GET'
        response = make_response('', 200)
        response.headers['X-Client-ID'] = kwargs.get('client_id')
        return response

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes'

@auth_blueprint.route('/oauth/token', methods=['POST', 'GET'])
@database.oauth.token_handler
def access_token():
    return {}

@auth_blueprint.route('/oauth/revoke', methods=['POST'])
@database.oauth.revoke_handler
def revoke_token():
    pass
