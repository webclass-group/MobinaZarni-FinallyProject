import os
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth

# ================== APP CONFIG ==================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")
app.config['GOOGLE_CLIENT_ID'] = 'YOUR_GOOGLE_CLIENT_ID'
app.config['GOOGLE_CLIENT_SECRET'] = 'YOUR_GOOGLE_CLIENT_SECRET'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
oauth = OAuth(app)

google = oauth.register(
    'google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    refresh_token_url=None,
    client_kwargs={'scope': 'openid profile email'},
)

# ================== MODEL ==================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    city = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), default="user")

# ================== SITE ROUTES ==================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    email = request.form['email']

    if User.query.filter_by(email=email).first():
        return "❌ این ایمیل قبلاً ثبت شده"

    user = User(
        first_name=request.form['first_name'],
        last_name=request.form['last_name'],
        city=request.form['city'],
        email=email,
        password=generate_password_hash(request.form['password']),
        role="user"
    )

    db.session.add(user)
    db.session.commit()
    return redirect('/')

@app.route('/login')
def login():
    redirect_uri = url_for('google_login', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/callback')
def google_login():
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token)

    # Check if user exists in DB
    user_in_db = User.query.filter_by(email=user_info['email']).first()
    if user_in_db:
        session['user_id'] = user_in_db.id
        session['user_role'] = user_in_db.role
        session['user_name'] = user_in_db.first_name
    else:
        # If user does not exist, create a new user
        new_user = User(
            first_name=user_info['given_name'],
            last_name=user_info['family_name'],
            email=user_info['email'],
            password='',  # No password needed for Google login
            role='user'   # Default role
        )
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        session['user_role'] = new_user.role
        session['user_name'] = new_user.first_name

    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    if session['user_role'] == 'admin':
        return f"""
        <h2>🛡️ پنل ادمین</h2>
        <p>خوش آمدید {session['user_name']}</p>
        <ul>
            <li><a href="/users">📋 مشاهده لیست کاربران</a></li>
            <li><a href="/api/users">🔗 API لیست کاربران (JSON)</a></li>
            <li><a href="/logout">🚪 خروج</a></li>
        </ul>
        """
    return f"""
    <h2>👤 پنل کاربر</h2>
    <p>خوش آمدید {session['user_name']}</p>
    <a href="/logout">🚪 خروج</a>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ================== USERS PAGE (ADMIN ONLY) ==================
@app.route('/users')
def users_list():
    if 'user_id' not in session:
        return redirect('/')

    if session.get('user_role') != 'admin':
        abort(403)

    users = User.query.all()
    return render_template('users.html', users=users)

# ================== REST API ==================
@app.route('/api')
def api_home():
    return jsonify({
        "message": "Flask REST API is working",
        "status": "OK"
    })

@app.route('/api/users')
def api_users():
    if session.get('user_role') != 'admin':
        abort(403)

    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "first_name": u.first_name,
        "last_name": u.last_name,
        "city": u.city,
        "email": u.email,
        "role": u.role
    } for u in users])

@app.route('/api/users/<int:user_id>')
def api_user_detail(user_id):
    if session.get('user_role') != 'admin':
        abort(403)

    user = User.query.get_or_404(user_id)
    return jsonify({
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "city": user.city,
        "email": user.email,
        "role": user.role
    })

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    if not data:
        return jsonify({"error": "JSON required"}), 400

    user = User.query.filter_by(email=data.get('email')).first()

    if user and check_password_hash(user.password, data.get('password')):
        return jsonify({
            "status": "success",
            "user": {
                "id": user.id,
                "name": user.first_name,
                "role": user.role
            }
        })

    return jsonify({
        "status": "error",
        "message": "Invalid credentials"
    }), 401

@app.route('/debug/users')
def debug_users():
    users = User.query.all()
    return jsonify([{
        "email": u.email,
        "role": u.role
    } for u in users])

# ================== RUN ==================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create database tables if not exist

        # Add default admin user if not already in the database
        if not User.query.filter_by(email="mobina13mo@gmail.com").first():
            admin = User(
                first_name="Mobina",
                last_name="Zarni",
                city="Zanjan",
                email="mobina13mo@gmail.com",
                password=generate_password_hash("admin123"),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()

    app.run(debug=True)
