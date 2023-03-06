from flask import Flask
from flask_login import LoginManager
from flask_oauthlib.provider import OAuth2Provider
from sqlalchemy import select
from miners_auth.database import init_db
from miners_auth import database

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'
init_db(app)

from miners_auth.routes.auth import auth_blueprint
from miners_auth.routes.main import main_blueprint
from miners_auth.routes.api import api_blueprint
from miners_auth.models.account import *



app.register_blueprint(auth_blueprint)
app.register_blueprint(api_blueprint)
app.register_blueprint(main_blueprint)

login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our user table, use it in the query for the user
    user = User.query.filter_by(id=user_id).first()
    return user

if __name__ == "__main__":
    database.oauth.init_app(app)
    app.run()
