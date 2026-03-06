import io
import os
import uuid
import zipfile
import tempfile
from datetime import datetime, timedelta

import stripe
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
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

BASE_URL = 'https://www.docutool.org'


# ── MODELS ────────────────────────────────────────────────────────────────────

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


# ── AUTH HELPERS ──────────────────────────────────────────────────────────────

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def create_user_from_checkout_session(checkout_session):
    pending_id = checkout_session.get('client_reference_id')
    if not pending_id:
        return None

    pending_signup = PendingSignup.query.filter_by(id=pending_id).first()
    if not pending_signup:
        return None

    existing_user = User.query.filter_by(email=pending_signup.email).first()
    if existing_user:
        if not existing_user.stripe_customer_id:
            existing_user.stripe_customer_id = checkout_session.get('customer')
        if not existing_user.stripe_subscription_id:
            existing_user.stripe_subscription_id = checkout_session.get('subscription')
        db.session.delete(pending_signup)
        db.session.commit()
        return existing_user

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
    return user


# ── CORE ROUTES ───────────────────────────────────────────────────────────────

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

    user = create_user_from_checkout_session(checkout_session)
    if user:
        login_user(user)
        return redirect(url_for('dashboard'))

    flash('Payment received but account setup failed. Please contact support.')
    return redirect(url_for('login'))


@app.route('/checkout/cancel')
def checkout_cancel():
    return render_template('cancel.html')


# ── STRIPE WEBHOOK ────────────────────────────────────────────────────────────

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

    elif event['type'] == 'customer.subscription.deleted':
        sub = event['data']['object']
        user = User.query.filter_by(stripe_subscription_id=sub['id']).first()
        if user:
            user.plan = 'cancelled'
            db.session.commit()

    elif event['type'] == 'customer.subscription.updated':
        sub = event['data']['object']
        user = User.query.filter_by(stripe_subscription_id=sub['id']).first()
        if user:
            if sub['status'] == 'active':
                user.plan = user.plan if user.plan in ['basic', 'pro'] else 'basic'
            elif sub['status'] in ['canceled', 'unpaid', 'past_due']:
                user.plan = 'cancelled'
            db.session.commit()

    return 'OK', 200


# ── LOGIN / LOGOUT ────────────────────────────────────────────────────────────

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


# ── DASHBOARD ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user, now=datetime.utcnow())


# ── ACCOUNT & BILLING ─────────────────────────────────────────────────────────

@app.route('/account')
@login_required
def account():
    trial_end = None
    subscription_status = 'inactive'
    cancel_at_period_end = False
    current_period_end = None

    if current_user.stripe_subscription_id:
        try:
            sub = stripe.Subscription.retrieve(current_user.stripe_subscription_id)
            subscription_status = sub.status
            cancel_at_period_end = sub.cancel_at_period_end
            current_period_end = datetime.utcfromtimestamp(sub.current_period_end).strftime('%B %d, %Y')
            if sub.status == 'trialing' and sub.trial_end:
                trial_end = datetime.utcfromtimestamp(sub.trial_end).strftime('%B %d, %Y')
        except Exception:
            pass

    return render_template(
        'account.html',
        user=current_user,
        subscription_status=subscription_status,
        cancel_at_period_end=cancel_at_period_end,
        current_period_end=current_period_end,
        trial_end=trial_end
    )


@app.route('/billing')
@login_required
def billing():
    return redirect(url_for('account'))


@app.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    if not current_user.stripe_subscription_id:
        flash('No active subscription found.')
        return redirect(url_for('dashboard'))

    try:
        stripe.Subscription.modify(
            current_user.stripe_subscription_id,
            cancel_at_period_end=True
        )
        flash('Your subscription has been cancelled. You will retain access until the end of your billing period.')
    except Exception as e:
        flash(f'Error cancelling subscription: {str(e)}')

    return redirect(url_for('dashboard'))


# ── TOOLS ─────────────────────────────────────────────────────────────────────

@app.route('/merge', methods=['GET', 'POST'])
@login_required
def merge():
    if request.method == 'POST':
        files = request.files.getlist('pdfs')
        mode = request.form.get('mode', 'single')

        if len(files) < 2:
            flash('Please upload at least 2 PDF files.')
            return redirect(url_for('merge'))

        for f in files:
            if not f.filename.lower().endswith('.pdf'):
                flash('All files must be PDFs.')
                return redirect(url_for('merge'))

        try:
            from pypdf import PdfWriter

            if mode == 'zip':
                writer = PdfWriter()
                for f in files:
                    writer.append(f)

                merged_pdf = io.BytesIO()
                writer.write(merged_pdf)
                merged_pdf.seek(0)

                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr('merged.pdf', merged_pdf.read())
                zip_buffer.seek(0)

                return send_file(
                    zip_buffer,
                    mimetype='application/zip',
                    as_attachment=True,
                    download_name='merged.zip'
                )
            else:
                writer = PdfWriter()
                for f in files:
                    writer.append(f)

                output = io.BytesIO()
                writer.write(output)
                output.seek(0)

                return send_file(
                    output,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name='merged.pdf'
                )

        except Exception as e:
            flash(f'Error merging PDFs: {str(e)}')
            return redirect(url_for('merge'))

    return render_template('merge.html')


@app.route('/convert', methods=['GET', 'POST'])
@login_required
def convert():
    if request.method == 'POST':
        files = request.files.getlist('pdfs')

        if not files or all(f.filename == '' for f in files):
            flash('Please upload at least one PDF file.')
            return redirect(url_for('convert'))

        for f in files:
            if not f.filename.lower().endswith('.pdf'):
                flash('All files must be PDFs.')
                return redirect(url_for('convert'))

        try:
            from pdf2docx import Converter as PDFConverter

            if len(files) == 1:
                f = files[0]
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
                    f.save(tmp_pdf.name)
                    tmp_pdf_path = tmp_pdf.name

                tmp_docx_path = tmp_pdf_path.replace('.pdf', '.docx')
                cv = PDFConverter(tmp_pdf_path)
                cv.convert(tmp_docx_path)
                cv.close()

                with open(tmp_docx_path, 'rb') as docx_file:
                    docx_bytes = io.BytesIO(docx_file.read())
                docx_bytes.seek(0)

                os.unlink(tmp_pdf_path)
                os.unlink(tmp_docx_path)

                original_name = os.path.splitext(f.filename)[0]
                return send_file(
                    docx_bytes,
                    mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                    as_attachment=True,
                    download_name=f'{original_name}.docx'
                )

            else:
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for f in files:
                        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
                            f.save(tmp_pdf.name)
                            tmp_pdf_path = tmp_pdf.name

                        tmp_docx_path = tmp_pdf_path.replace('.pdf', '.docx')
                        cv = PDFConverter(tmp_pdf_path)
                        cv.convert(tmp_docx_path)
                        cv.close()

                        original_name = os.path.splitext(f.filename)[0]
                        with open(tmp_docx_path, 'rb') as docx_file:
                            zf.writestr(f'{original_name}.docx', docx_file.read())

                        os.unlink(tmp_pdf_path)
                        os.unlink(tmp_docx_path)

                zip_buffer.seek(0)
                return send_file(
                    zip_buffer,
                    mimetype='application/zip',
                    as_attachment=True,
                    download_name='converted.zip'
                )

        except Exception as e:
            flash(f'Error converting PDF: {str(e)}')
            return redirect(url_for('convert'))

    return render_template('convert.html')


@app.route('/compress', methods=['GET', 'POST'])
@login_required
def compress():
    if request.method == 'POST':
        files = request.files.getlist('pdfs')

        if not files or all(f.filename == '' for f in files):
            flash('Please upload at least one PDF file.')
            return redirect(url_for('compress'))

        for f in files:
            if not f.filename.lower().endswith('.pdf'):
                flash('All files must be PDFs.')
                return redirect(url_for('compress'))

        try:
            from pypdf import PdfWriter, PdfReader

            if len(files) == 1:
                f = files[0]
                reader = PdfReader(f)
                writer = PdfWriter()

                for page in reader.pages:
                    writer.add_page(page)

                for page in writer.pages:
                    page.compress_content_streams()

                if reader.metadata:
                    writer.add_metadata(reader.metadata)

                output = io.BytesIO()
                writer.write(output)
                output.seek(0)

                original_name = os.path.splitext(f.filename)[0]
                return send_file(
                    output,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=f'{original_name}_compressed.pdf'
                )

            else:
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for f in files:
                        reader = PdfReader(f)
                        writer = PdfWriter()

                        for page in reader.pages:
                            writer.add_page(page)

                        for page in writer.pages:
                            page.compress_content_streams()

                        if reader.metadata:
                            writer.add_metadata(reader.metadata)

                        compressed = io.BytesIO()
                        writer.write(compressed)
                        compressed.seek(0)

                        original_name = os.path.splitext(f.filename)[0]
                        zf.writestr(f'{original_name}_compressed.pdf', compressed.read())

                zip_buffer.seek(0)
                return send_file(
                    zip_buffer,
                    mimetype='application/zip',
                    as_attachment=True,
                    download_name='compressed.zip'
                )

        except Exception as e:
            flash(f'Error compressing PDF: {str(e)}')
            return redirect(url_for('compress'))

    return render_template('compress.html')


# ── INIT ──────────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
