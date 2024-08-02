"""
JOSHUA HAYHURST
SDEV300
6 October 2021

This program is for a flask website server for cooking.
It has a login, account registration, and a password
reset feature.
"""
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, request
from passlib.hash import sha256_crypt
import json

app = Flask(__name__)
app.secret_key = '12345'


@app.route('/')
def index():
    """assigns login.html login webpage upon launch"""
    return login()


@app.route('/login', methods=['GET', 'POST'])
def login():
    """function for logging in using user provided credentials
    pulls username/password from login.html form and checks with
    known database"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        js = get_passfile()  # grabs current login database
        if check_login(username, password):
            if username in js:  # checks user as dict key
                if sha256_crypt.verify(password, js[username]):  # verifies user credentials match db
                    return redirect(url_for("home"))
        flash("Invalid username/password combination")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """function for registering a new account, pulls user
    provided information from register.html form and runs
    account and password through check functions. If checks
    pass, then user account/password are stored in db"""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        repeat = request.form["repeat"]
        js = get_passfile()
        if check_account(username):
            flash("Username is already registered")  # passes error if username is already registered
        elif check_password(password, repeat):  # if password is good
            js[username] = sha256_crypt.hash(password)  # encrypt password and store user/hash to db
            save_passfile(js)  # save current db
            flash("Account Registration Complete")
            return redirect(url_for("login"))  # return to login if successful

        return redirect(url_for("register"))  # return to register if not successful

    return render_template('register.html')


@app.route('/recover', methods=['GET', 'POST'])
@app.route('/recover/<username>', methods=['GET', 'POST'])
def recover(username=None):
    """function resets user's password. loads either of two forms in page
    depending on if username is provided. First form requests account/username,
    and second form is for password reset. Account must exist for second form to load
    and password is run through same checks."""
    js = get_passfile()  # gets current db
    if request.method == "POST":
        # grabs which button for which form was used
        if request.form['submit_button'] == 'Next':  # if "Next" button used, perform username check
            username = request.form["username"]
            if not username:
                flash("Username is required")
                return redirect(url_for("recover"))
            elif username in js:
                return redirect(url_for("recover", username=username))  # reload page with username address
            else:
                flash("Username is not registered to a known account")
                return redirect(url_for("recover"))

        elif request.form['submit_button'] == 'Submit':  # if "Submit" button used, perform password checks
            password = request.form['password']
            repeat = request.form['repeat']
            if check_password(password, repeat):
                js[username] = sha256_crypt.hash(password)
                save_passfile(js)
                flash('Password Updated')
                return redirect(url_for("login"))
    return render_template('recover.html', username=username)


@app.route('/home')
def home():
    """assigns home.html website homepage"""
    return render_template('home.html', datetime=str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")))


@app.route('/sourdough')
def sourdough():
    """assigns sourdough route to sourdough.html introduction page"""
    return render_template('sourdough.html')


@app.route('/sourdough/ingredients')
def sourdough_ingredients():
    """assigns ingredients route for sourdough recipe"""
    return render_template('ingredients.html')


@app.route('/sourdough/instructions')
def sourdough_instructions():
    """assigns instructions route for sourdough recipe"""
    return render_template('instructions.html')


def check_login(user, passw):
    """function for checking user login fields are filled"""
    pass_fail = True
    if not user:
        flash("Username is required.")
        pass_fail = False
    elif not passw:
        flash("Password is required.")
        pass_fail = False
    return pass_fail


def get_passfile():
    """gets the most current user login db"""
    with open('passfile') as f:
        js = json.loads(f.read())  # loads file as json and stores as dict
    return js


def save_passfile(js_data):
    """saves js db to passfile"""
    with open('passfile', 'w') as f:
        f.write(json.dumps(js_data))


def check_account(user):
    """checks if user exists in user login db"""
    js = get_passfile()
    if user in js:
        return True
    else:
        return False


def check_password(passw, repeat):
    """function for various password checks"""
    symbol = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '=', '+',
              '[', ']', '{', '}', ':', ';', '\'', '"', ',', '.', '<', '>', '/', '?']
    pass_fail = True

    if not passw:
        flash("Password is required.")
        pass_fail = False

    elif passw != repeat:
        flash("Passwords don't match")
        pass_fail = False

    else:
        with open('CommonPassword.txt', 'r') as f:
            lines = f.readlines()
            for line in lines:
                if passw == line.strip():
                    flash('Password is too common. Use a different password')
                    pass_fail = False

        if len(passw) < 12:
            flash("Password must be 12 characters minimum")
            pass_fail = False

        if not any(char.isdigit() for char in passw):
            flash('Password should have at least one numeral')
            pass_fail = False

        if not any(char.isupper() for char in passw):
            flash('Password should have at least one uppercase letter')
            pass_fail = False

        if not any(char.islower() for char in passw):
            flash('Password should have at least one lowercase letter')
            pass_fail = False

        if not any(char in symbol for char in passw):
            flash('Password should have at least one special symbol')
            pass_fail = False

    return pass_fail
