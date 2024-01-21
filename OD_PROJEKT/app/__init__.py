from flask import Flask, request
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ifjdsaifjdaskfmlk'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

#limit.init_app(app)

from app import routes
from app import models
