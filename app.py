import os
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ================== APP CONFIG ==================
app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "fallback-secret-key")

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

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

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()

    if user and check_password_hash(user.password, request.form['password']):
        session['user_id'] = user.id
        session['user_role'] = user.role
        session['user_name'] = user.first_name
        return redirect('/dashboard')

    return "❌ ایمیل یا رمز عبور اشتباه است"

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')

    if session['user_role'] == 'admin':
        return f"🛡️ پنل ادمین | خوش آمدی {session['user_name']}"
    else:
        return f"👤 پنل کاربر | خوش آمدی {session['user_name']}"

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ================== REST API ==================

@app.route('/api')
def api_home():
    return jsonify({"message": "Flask REST API is working", "status": "OK"})

# 🔐 فقط admin اجازه دیدن همه کاربران
@app.route('/api/users')
def api_users():
    if session.get('user_role') != 'admin':
        abort(403)

    users = User.query.all()
    return jsonify([
        {
            "id": u.id,
            "first_name": u.first_name,
            "last_name": u.last_name,
            "city": u.city,
            "email": u.email,
            "role": u.role
        } for u in users
    ])

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

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# ================== RUN ==================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    
