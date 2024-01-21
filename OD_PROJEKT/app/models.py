from flask_login import UserMixin

from app import login_manager, db, app


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    account_number = db.Column(db.String(26), unique=True, nullable=False)
    password_full = db.Column(db.String(60), unique=True, nullable=False)
    card_number = db.Column(db.String(60), unique=True, nullable=False)
    id_number = db.Column(db.String(60), unique=True, nullable=False)

class Transfer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
    #return User()



with app.app_context():
    db.create_all()