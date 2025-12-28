from flask import Flask, render_template, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "super-secret-key"   # 🔐 مهم

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ===== MODEL =====
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    city = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(10), default="user")


# ===== ROUTES =====
@app.route('/')
def index():
    return render_template('index.html')


# ===== REGISTER =====
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
        role="user"   # 🔒 نقش فقط از سمت سرور
    )

    db.session.add(user)
    db.session.commit()

    return redirect('/')


# ===== LOGIN =====
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        # 🔐 ذخیره اطلاعات در session
        session['user_id'] = user.id
        session['user_role'] = user.role
        session['user_name'] = user.first_name

        # 🔁 هدایت بر اساس نقش
        if user.role == "admin":
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))

    return "❌ ایمیل یا رمز عبور اشتباه است"


# ===== USER DASHBOARD =====
@app.route('/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        return redirect('/')

    return f"👤 خوش آمدی {session['user_name']} (USER)"


# ===== ADMIN DASHBOARD =====
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != "admin":
        return "⛔ دسترسی غیرمجاز"

    return f"🛡 خوش آمدی {session['user_name']} (ADMIN)"


# ===== LOGOUT =====
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# ===== RUN =====
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True) 