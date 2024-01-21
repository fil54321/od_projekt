import base64
import random
import string
import time

import zxcvbn
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, current_user, login_required
from app import app, db, limiter, bcrypt
from app.forms import RegistrationForm, LoginForm, MakeTransferForm, ShowHideForm, ChangePasswordForm
from app.models import load_user, User, Transfer


@app.route('/')
def home():
    return render_template('index.html', a=5)

@app.route('/before_data', methods=['GET', 'POST'])
@login_required
def before_data():
    form = ShowHideForm()
    if request.method == 'POST':
        show_data = False
        decrypted_card_data = b''
        decrypted_id_data = b''
        if request.form.get('action') == 'show':
            show_data = True
            user = current_user
            iv = user.password_full[29:45].encode('utf-8')
            key = user.password_full[7:23].encode('utf-8')
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_card_data = base64.b64decode(user.card_number)
            decrypted_card_data = unpad(cipher.decrypt(encrypted_card_data), AES.block_size)
            encrypted_id_data = base64.b64decode(user.id_number)
            decrypted_id_data = unpad(cipher.decrypt(encrypted_id_data), AES.block_size)
        return render_template('data.html', form=form, show_data=show_data,
                               decrypted_id_data=decrypted_id_data.decode('utf-8'),
                               decrypted_card_data=decrypted_card_data.decode('utf-8'))

    return render_template('data.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/transfers', methods=['GET'])
@login_required
def list_transfers():
    sent_transfers = Transfer.query.filter_by(sender_id=current_user.id).all()
    received_transfers = Transfer.query.filter_by(recipient_id=current_user.id).all()
    sent_transfers_info = []
    for transfer in sent_transfers:
        recipient = User.query.get(transfer.recipient_id)
        sent_transfers_info.append({'transfer': transfer, 'recipient': recipient})
    received_transfers_info = []
    for transfer in received_transfers:
        sender = User.query.get(transfer.sender_id)
        received_transfers_info.append({'transfer': transfer, 'sender': sender})
    return render_template('transfers.html', sent=sent_transfers_info, received=received_transfers_info)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("4 per minute")
def login():
    form = LoginForm()
    user = User.query.filter_by(username=form.username.data).first()
    if form.validate_on_submit() and user and bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user)
        return redirect(url_for('home'))
    if request.method == 'POST':
        time.sleep(3)
    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        score = zxcvbn.zxcvbn(form.password.data)['score']
        #print(score)
        if score <= 3:
            flash('Haslo za slabe', 'danger')
            return render_template('register.html', form=form)
        account_number = ''.join(random.choices(string.digits, k=26))
        card_number = ''.join(random.choices(string.digits, k=16))
        id_number = "DBD" + ''.join(random.choices(string.digits, k=6))
        password_full = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        selected_password = form.password.data[0] + form.password.data[2] + form.password.data[4]
        hashed_password = bcrypt.generate_password_hash(selected_password).decode('utf-8')

        iv = password_full[29:45].encode('utf-8')
        key = password_full[7:23].encode('utf-8')
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data_c = pad(card_number.encode('utf-8'), AES.block_size)
        padded_data_i = pad(id_number.encode('utf-8'), AES.block_size)
        encrypted_data_c = cipher.encrypt(padded_data_c)
        encrypted_data_i = cipher.encrypt(padded_data_i)

        user = User(username=form.username.data, password=hashed_password, account_number=account_number,
                    password_full=password_full,
                    card_number=base64.b64encode(encrypted_data_c).decode('utf-8'),
                    id_number=base64.b64encode(encrypted_data_i).decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/make_transfer', methods=['GET', 'POST'])
@login_required
def make_transfer():
    form = MakeTransferForm()
    users = User.query.filter(User.id != current_user.id).all()
    #users = User.query.all()
    form.account_number.choices = [(user.id, user.account_number + " - " + user.username) for user in users]
    print([(user.id, user.username) for user in User.query.all()])
    if request.method == 'POST' and form.validate_on_submit():
        amount = form.amount.data
        title = form.title.data
        recipient_id = form.account_number.data
        transfer = Transfer(amount=amount, title=title, sender_id=current_user.id, recipient_id=recipient_id)
        db.session.add(transfer)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('makeTransfer.html', form=form)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        score = zxcvbn.zxcvbn(form.new_password.data)['score']
        # print(score)
        if score <= 3:
            flash('Password is too weak', 'danger')
            return render_template('changePasswrod.html', form=form)
        if bcrypt.check_password_hash(current_user.password_full, form.current_password.data):
            new_password_hash = bcrypt.generate_password_hash(form.new_password.data).decode('utf-8')
            selected_password = form.new_password.data[0] + form.new_password.data[2] + form.new_password.data[4]
            old_password_full = current_user.password_full
            old_password = current_user.password
            iv = old_password_full[29:45].encode('utf-8')
            key = old_password_full[7:23].encode('utf-8')
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted_card_data = base64.b64decode(current_user.card_number)
            decrypted_card_data = unpad(cipher.decrypt(encrypted_card_data), AES.block_size)
            encrypted_id_data = base64.b64decode(current_user.id_number)
            decrypted_id_data = unpad(cipher.decrypt(encrypted_id_data), AES.block_size)
            current_user.password_full = new_password_hash
            current_user.password =  bcrypt.generate_password_hash(selected_password).decode('utf-8')
            iv = current_user.password_full[29:45].encode('utf-8')
            key = current_user.password_full[7:23].encode('utf-8')
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data_c = pad(decrypted_card_data.decode('utf-8').encode('utf-8'), AES.block_size)
            padded_data_i = pad(decrypted_id_data.decode('utf-8').encode('utf-8'), AES.block_size)
            encrypted_data_c = cipher.encrypt(padded_data_c)
            encrypted_data_i = cipher.encrypt(padded_data_i)
            current_user.card_number = base64.b64encode(encrypted_data_c).decode('utf-8')
            current_user.id_number = base64.b64encode(encrypted_data_i).decode('utf-8')
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('Current password is incorrect', 'danger')
    return render_template('changePasswrod.html', form=form)
