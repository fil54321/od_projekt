import zxcvbn
from flask_wtf import FlaskForm
from wtforms import validators
from wtforms.fields.choices import SelectField
from wtforms.fields.numeric import FloatField
from wtforms.fields.simple import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, NumberRange, EqualTo


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[
        DataRequired(), lambda form, field: Length(min=6)(form, field)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ShowHideForm(FlaskForm):
    pass

class MakeTransferForm(FlaskForm):
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0, max=15000, message="Amount must be between 0 and 15000 PLN")
    ])
    title = StringField('Title', validators=[DataRequired()])
    account_number = SelectField('Recipient Name', coerce=int, validators=[DataRequired()])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), lambda form, field: Length(min=6)(form, field)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('new_password', message='Passwords must match')])
    submit = SubmitField('Change Password')