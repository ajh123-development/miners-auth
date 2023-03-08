from flask import Blueprint, render_template, redirect, url_for
from flask_login import login_required, current_user


main_blueprint = Blueprint('main', __name__)

@main_blueprint.route('/')
def index():
    return render_template('index.html', user=current_user)

@main_blueprint.route('/settings')
@login_required
def settings():
    return redirect(url_for('main.profile'))

@main_blueprint.route('/settings/profile')
@login_required
def profile():
    return render_template('settings/profile.html', user=current_user, hideHero=True, hideContents=True)

@main_blueprint.route('/settings/apps')
@login_required
def apps():
    return render_template('settings/apps.html', user=current_user, hideHero=True, hideContents=True)
