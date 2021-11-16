from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# Line below only required once, when creating DB.
# db.create_all()




@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    elif request.method == 'POST':
        user_password = request.form.get('password')
        hashed_password = generate_password_hash(user_password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=request.form.get('email'),
            password=hashed_password,
            name=request.form.get('name')
        )
        user_find = User.query.filter_by(email=new_user.email).first()
        if user_find:
            flash('Email address already exists, please login instead')
            return redirect(url_for('login'))
        db.session.add(new_user)
        db.session.commit()
        return render_template("secrets.html", name=new_user.name)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("login.html", logged_in=current_user.is_authenticated)
    elif request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if the user doesn't exist or password is wrong, reload the page
        else:
            login_user(user)
            return render_template("secrets.html", logged_in=True)


@login_required
@app.route('/secrets/')
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@login_required
@app.route('/download/<path:filename>')
def download(filename):
    directory = 'static/files/'
    return send_from_directory(directory=directory, filename=filename)


if __name__ == "__main__":
    app.run(debug=True)
