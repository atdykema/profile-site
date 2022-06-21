from crypt import methods
import re
from flask import Flask, render_template, url_for, request, session, redirect
from pymongo import MongoClient
import bcrypt
import sys
import certifi
from dotenv import load_dotenv
import os

app = Flask(__name__)

load_dotenv()
client = MongoClient(os.environ.get("MONGO_URI"), tlsCAFile=certifi.where())
db = client[os.environ.get("DB_NAME")]


@app.route("/")
def index():
    if 'email' not in session:
        return redirect(url_for('login'))

    return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template("login.html")

    elif request.method == 'POST':
        users = db.users
        login_user = users.find_one({'email' : request.form['email']})

        if login_user:
            if bcrypt.hashpw(request.form['password'].encode('utf-8'), login_user['password']) == login_user['password']:
                session['email'] = request.form['email']
                return redirect(url_for('index'))
            else:
                err = "Incorrect password"
        else:
            err = "User not found"

        return render_template("login.html", err=err)


@app.route("/signup", methods=['GET', 'POST'])
def signup():

    if request.method == 'GET':
        return render_template("signup.html")

    elif request.method == 'POST':
        users = db.users
        existing_user = users.find_one({'email' : request.form['email']})

        if existing_user is None and request.form['password'] == request.form['re_password']:
            hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            users.insert_one({'email' : request.form['email'], 'password' : hashpass, 'items' : []})
            session['email'] = request.form['email']
            return redirect(url_for('index'))

        elif existing_user is not None:
            err = "Username already taken, please try again"

        elif request.form['password'] != request.form['re_password']:
            err = "Passwords do not match, please try again"
        
        return render_template("signup.html", err=err)


if __name__ == "__main__":
    app.secret_key = os.environ.get("SECRET_KEY")
    app.run(debug=True)
