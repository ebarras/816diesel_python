from flask import Flask, render_template, g, request, redirect, url_for, session
from flask.ext.session import Session
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm.exc import NoResultFound
from flask.ext.bcrypt import Bcrypt
from functools import wraps

app = Flask(__name__)
app.config.from_pyfile('config.py', silent=False)

bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
sess = Session(app)

# Create a table to support a many-to-many relationship between Users and Roles
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)
# Role class
class Role(db.Model):

    # Our Role has three fields, ID, name and description
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    # __str__ is required by Flask-Admin, so we can have human-readable values for the Role when editing a User.
    # If we were using Python 2.7, this would be __unicode__ instead.
    def __str__(self):
        return self.name

    # __hash__ is required to avoid the exception TypeError: unhashable type: 'Role' when saving a User
    def __hash__(self):
        return hash(self.name)

# User class
class User(db.Model):

    # Our User has six fields: ID, email, password, active, confirmed_at and roles. The roles field represents a
    # many-to-many relationship using the roles_users table. Each user may have no role, one role, or multiple roles.
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship(
        'Role',
        secondary=roles_users,
        backref=db.backref('users', lazy='dynamic')
    )

# Executes before the first request is processed.
@app.before_first_request
def before_first_request():
    # Create the tables if they aren't there.
    db.create_all()

    # Add some roles to the DB if they don't exist.
    role = Role.query.filter_by(name='admin').first()
    if (not role):
        role = Role(name='admin', description='Administrator');
        db.session.add(role)

    role = Role.query.filter_by(name='user').first()
    if (not role):
        role = Role(name='user', description='User');
        db.session.add(role)

    # Add some users to the DB if they don't exist (for testing).
    user = User.query.filter_by(email='admin@816diesel.com').first()
    if (not user):
        user = User(email='admin@816diesel.com', password=bcrypt.generate_password_hash('password', 12), active=1);
        role = Role.query.filter_by(name='admin').first()
        user.roles.append(role)
        db.session.add(user)

    user = User.query.filter_by(email='user@816diesel.com').first()
    if (not user):
        user = User(email='user@816diesel.com', password=bcrypt.generate_password_hash('password', 12), active=1);
        role = Role.query.filter_by(name='user').first()
        user.roles.append(role)
        db.session.add(user)

    db.session.commit()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
@login_required
def admin():
    return 'ADMIN PAGE'

@app.route('/admin/users')
@login_required
def admin_users():
    return 'USER ADMIN PAGE'

@app.route('/admin/roles')
@login_required
def admin_roles():
    return 'ROLES ADMIN PAGE'

@app.route('/login')
def login():
    # Here we write the login.

    # Login Page needs a view that sends email and pass. bcrypt the pass and check both against the database. If the user is
    #  in the database, set the session to the user so we have all their data. Include user rolls for auth stuff.

    session['user'] = 'Erik'
    return 'LOGIN PAGE GOES HERE'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
# If running locally, listen on all IP addresses, port 8080
if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=int('1337'),
        debug=app.config['DEBUG']
    )