import os
import uuid
from datetime import datetime, timedelta

import stripe
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change_this_to_a_long_random_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
STRIPE_BASIC_PRICE_ID = os.getenv('STRIPE_BASIC_PRICE_ID')
STRIPE_PRO_PRICE_ID = os.getenv('STRIPE_PRO_PRICE_ID')
STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET')

BASE_URL = 'https://docutool-azg1.onrender.com'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    plan = db.Column(db.String(50), default='basic')
    stripe_customer_id = db.Column(db.String(255), nullable=True)
    stripe_subscription_id = db.Column(db.String(255), nullable=True)
    trial_ends_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PendingSignup(db.Model):
    id = db.Column(db.String(64), primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    plan = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_user_from_checkout_session(checkout_session):
    pending_id = checkout_session.get('client_reference_id')
    if not pending_id:
        return

    pending_signup = PendingSignup.query.filter_by(id=pending_id).first()
    if not pending_signup:
        return

    existing_user = User.query.filter_by(email=pending_signup.email).first()
    if existing_user:
        if not existing_user.stripe_customer_id:
            existing_user.stripe_customer_id = checkout_session.get('customer')
        if not existing_user.stripe_subscription_id:
            existing_user.stripe_subscription_id = checkout_session.get('subscription')
        db.session.delete(pending_signup)
        db.session.commit()
        return

    user = User(
        email=pending_signup.email,
        password=pending_signup.password_hash,
        plan=pending_signup.plan,
        stripe_customer_id=checkout_session.get('customer'),
        stripe_subscription_id=checkout_session.get('subscription'),
        trial_ends_at=datetime.utcnow() + timedelta(days=3)
    )

    db.session.add(user)
    db.session.delete(pending_signup)
    db.session.commit()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        plan = request.form.get('plan', 'basic')

        if plan not in ['basic', 'pro']:
            flash('Please choose a valid plan.')
            return redirect(url_for('register'))

        if password != confirm:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))

        existing_pending = PendingSignup.query.filter_by(email=email).first()
        if existing_pending:
            db.session.delete(existing_pending)
            db.session.commit()

        pending_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)

        pending_signup = PendingSignup(
            id=pending_id,
            email=email,
            password_hash=password_hash,
            plan=plan
        )
        db.session.add(pending_signup)
        db.session.commit()

        price_id = STRIPE_BASIC_PRICE_ID if plan == 'basic' else STRIPE_PRO_PRICE_ID

        try:
            checkout_session = stripe.checkout.Session.create(
                mode='subscription',
                customer_email=email,
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                success_url=f'{BASE_URL}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}',
                cancel_url=f'{BASE_URL}/checkout/cancel',
                client_reference_id=pending_id,
                subscription_data={
                    'trial_period_days': 3
                }
            )
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            db.session.delete(pending_signup)
            db.session.commit()
            flash(f'Stripe error: {str(e)}')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/checkout/success')
def checkout_success():
    session_id = request.args.get('session_id')

    if not session_id:
        flash('Missing Stripe session ID.')
        return redirect(url_for('register'))

    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
    except Exception as e:
        flash(f'Could not verify checkout: {str(e)}')
        return redirect(url_for('register'))

    if checkout_session.status != 'complete':
        flash('Checkout was not completed.')
        return redirect(url_for('register'))

    existing_user = User.query.filter_by(email=checkout_session.customer_email).first()
    if existing_user:
        login_user(existing_user)
        return redirect(url_for('dashboard'))

    flash('Payment received. Your account is being finalized. Please log in in a few seconds.')
    return redirect(url_for('login'))


@app.route('/checkout/cancel')
def checkout_cancel():
    return render_template('cancel.html')


@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')

    try:
        event = stripe.Webhook.construct_event(
            payload,
            sig_header,
            STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400

    if event['type'] == 'checkout.session.completed':
        checkout_session = event['data']['object']
        create_user_from_checkout_session(checkout_session)

    return 'OK', 200


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Invalid email or password.')
            return redirect(url_for('login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)


@app.route('/merge')
@login_required
def merge():
    return '<h2>PDF Merge tool coming next</h2>'


@app.route('/convert')
@login_required
def convert():
    return '<h2>PDF ↔ Word tool coming next</h2>'


@app.route('/compress')
@login_required
def compress():
    return '<h2>Compression tool coming next</h2>'


with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)
