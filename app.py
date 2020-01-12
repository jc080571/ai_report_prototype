# -*- coding: UTF-8 -*-
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, Form, TextField, TextAreaField, validators, SubmitField
from wtforms.validators import DataRequired
from models.Users import User
from models.Users import db
import re
from datetime import datetime
from elasticsearch import Elasticsearch
import json

# es = Elasticsearch()

# setup the app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = "SuperSecretKey"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)
bcrypt = Bcrypt(app)

# setup the login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# create the db structure
with app.app_context():
    db.create_all()

####  setup routes  ####
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)


@app.route("/login", methods=["GET", "POST"])
def login():

    # clear the inital flash message
    session.clear()
    if request.method == 'GET':
        return render_template('login.html')

    # get the form data
    username = request.form['username']
    password = request.form['password']

    remember_me = False
    if 'remember_me' in request.form:
        remember_me = True

    # query the user
    registered_user = User.query.filter_by(username=username).first()

    # check the passwords
    if registered_user is None and bcrypt.check_password_hash(registered_user.password, password) == False:
        flash('Invalid Username/Password')
        return render_template('login.html')

    # login the user
    login_user(registered_user, remember=remember_me)
    return redirect(request.args.get('next') or url_for('index'))


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        session.clear()
        return render_template('register.html')

    # get the data from our form
    password = request.form['password']
    conf_password = request.form['confirm-password']
    username = request.form['username']
    email = request.form['email']

    # check if it meets the right complexity
    check_account = account_check(username)
    
    # generate error messages if it doesnt pass
    if True in check_account.values():
        for k,v in check_account.iteritems():
            if str(v) is "True":
                flash(k)
        return render_template('register.html')

    # make sure the password match
    if conf_password != password:
        flash("Passwords do not match")
        return render_template('register.html')

    # check if it meets the right complexity
    check_password = password_check(password)
    
    # generate error messages if it doesnt pass
    if True in check_password.values():
        for k,v in check_password.iteritems():
            if str(v) is "True":
                flash(k)

        return render_template('register.html')

    # hash the password for storage
    pw_hash = bcrypt.generate_password_hash(password)

    # create a user, and check if its unique
    user = User(username, pw_hash, email)
    u_unique = user.unique()

    # add the user
    if u_unique == 0:
        db.session.add(user)
        db.session.commit()
        flash("Account Created")
    
        return redirect(url_for('login'))

    # else error check what the problem is
    elif u_unique == -1:
        flash("Email address already in use.")
        return render_template('register.html')

    elif u_unique == -2:
        flash("Username already in use.")
        return render_template('register.html')

    else:
        flash("Username and Email already in use.")
        return render_template('register.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('todaysnew'))

@app.route('/todaysnews',methods=['GET','POST'])
def todaysnews():
    cursor = db.engine.execute('SELECT source, author, title, description, url, urltoimage, publishedat,content,storyid,headline_ind  FROM news')

    return render_template('todaysnews.html', user=current_user,news=cursor.fetchall())

@app.route('/function_1')
def function_1():
    cursor = db.engine.execute('SELECT num,com_name,representative,business,bu,text FROM credit_data')
    return render_template('function_1.html', user=current_user,data=cursor.fetchall())

@app.route('/function_2')
def function_2():
    return render_template('function_2.html', user=current_user)

@app.route('/profile')
def profile():
    return render_template('profile.html', user=current_user)


####  end routes  ####


# required function for loading the right user
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# check password complexity
def password_check(password):

    # calculating the length
    length_error = len(password) <= 6

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    ret = {
        'Password is less than 6 characters' : length_error,
        'Password does not contain a number' : digit_error,
        'Password does not contain a uppercase character' : uppercase_error,
        'Password does not contain a lowercase character' : lowercase_error,
    }

    return ret

# check password complexity
def account_check(username):

    # calculating the length
    length_error = len(username) != 8

    # searching for uppercase
    esb_error = re.search(r"ESB|esb", username) is None


    ret = {
        'Please enter AD account(esb + 5 number)' : length_error,
        'Password does not contain esb or ESB character' : esb_error
    }

    return ret


if __name__ == "__main__":
	app.run() 