from flask import Flask, request, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, login_required, logout_user, LoginManager, UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
import requests
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///list.database'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
db = SQLAlchemy(app)

API_KEY = os.environ.get('API_KEY')
ENDPOINT = "https://api.api-ninjas.com/v1/bucketlist"

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f"{self.name} - {self.email} - {self.password}"

db.create_all()


@app.route("/")
def home():
    return render_template("home.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == 'POST':

        hashed_and_salted_password = generate_password_hash(
            request.form.get('password'),
            salt_length=10,
            method="pbkdf2:sha256"
        )

        new_user = Users(
            name=request.form.get("name"),
            email = request.form.get("email"),
            password = hashed_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('bucketlist'))

    return render_template('register.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get("password")

        user = Users.query.filter_by(name=name).first()
        if not user:
            flash("This username doesn't exist. Try again")
            return redirect(url_for('login'))

        elif not check_password_hash(pwhash=user.password, password=password):
            flash("Incorrect Password. Try again or register for an account")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for("bucketlist"))

    return render_template("login.html")


@app.route("/bucketlist")
@login_required
def bucketlist():
    response = requests.get(url=ENDPOINT, headers={"X-Api-Key": API_KEY})
    data = response.json()
    b_list = data["item"]
    return render_template('bucketlist.html', list_item=b_list)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
