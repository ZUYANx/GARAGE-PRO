import os
import uuid
import json
import csv
import zipfile
import io
from io import StringIO
from datetime import datetime, date, timedelta, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_, func

app = Flask(__name__)
app.config['SECRET_KEY'] = 'garage-pro-secure-key-2025'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///garage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024

db = SQLAlchemy(app)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'nid'), exist_ok=True)

# ---------- Models ----------
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='moderator')
    permissions = db.Column(db.Text, default='{}')
    is_active = db.Column(db.Boolean, default=True)
    language = db.Column(db.String(10), default='en')
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    activities = db.relationship('ActivityLog', backref='admin', lazy=True)

class Party(db.Model):
    __tablename__ = 'party'
    id = db.Column(db.String(20), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120))
    address = db.Column(db.Text)
    vehicle_number = db.Column(db.String(20))
    vehicle_model = db.Column(db.String(100))
    profile_pic = db.Column(db.String(200))
    nid_front = db.Column(db.String(200))
    nid_back = db.Column(db.String(200))
    total_due = db.Column(db.Float, default=0.0)
    total_paid = db.Column(db.Float, default=0.0)
    is_active = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    transactions = db.relationship('Transaction', backref='party', lazy=True, cascade='all, delete-orphan')
    vehicle_statuses = db.relationship('VehicleStatus', backref='party', lazy=True, cascade='all, delete-orphan')
    sms_logs = db.relationship('SmsLog', backref='party_sms', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.String(20), db.ForeignKey('party.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    description = db.Column(db.String(200))
    payment_method = db.Column(db.String(50))
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    bill_number = db.Column(db.String(50), unique=True)
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)

class GarageTransaction(db.Model):
    __tablename__ = 'garage_transaction'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)

class VehicleStatus(db.Model):
    __tablename__ = 'vehicle_status'
    id = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.String(20), db.ForeignKey('party.id'), nullable=False)
    status = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)

class SmsLog(db.Model):
    __tablename__ = 'sms_log'
    id = db.Column(db.Integer, primary_key=True)
    party_id = db.Column(db.String(20), db.ForeignKey('party.id'), nullable=True)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=True)
    action = db.Column(db.String(200), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(50))

# ---------- Helpers ----------
def generate_party_id():
    while True:
        pid = 'PRT' + str(uuid.uuid4().hex[:8]).upper()
        if not db.session.get(Party, pid):
            return pid

def generate_bill_number():
    while True:
        bill = 'BIL' + datetime.now().strftime('%Y%m%d') + str(uuid.uuid4().hex[:4]).upper()
        if not Transaction.query.filter_by(bill_number=bill).first():
            return bill

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please login first.', 'error')
            return redirect(url_for('login'))
        admin = db.session.get(Admin, session['admin_id'])
        if not admin or admin.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def permission_required(perm):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'admin_id' not in session:
                flash('Please login first.', 'error')
                return redirect(url_for('login'))
            admin = db.session.get(Admin, session['admin_id'])
            if admin and admin.role == 'admin':
                return f(*args, **kwargs)
            if admin and admin.permissions:
                try:
                    perms = json.loads(admin.permissions)
                except:
                    perms = {}
                if not perms.get(perm):
                    flash('Permission denied.', 'error')
                    return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def log_activity(action, details=None):
    if 'admin_id' in session:
        log = ActivityLog(admin_id=session['admin_id'], action=action, details=details, ip_address=request.remote_addr)
        db.session.add(log)
        db.session.commit()

def send_sms(phone, message):
    try:
        print(f"SMS to {phone}: {message}")
        return True
    except:
        return False

def get_current_permissions():
    if 'admin_id' not in session:
        return {}
    admin = db.session.get(Admin, session['admin_id'])
    if admin and admin.role == 'admin':
        return {'all': True}
    if admin and admin.permissions:
        try:
            return json.loads(admin.permissions)
        except:
            return {}
    return {}

# ---------- Translations ----------
translations = {
    'en': {
        'home': 'Home', 'transactions': 'Transactions', 'parties': 'Parties',
        'garage_expenses': 'Garage Expenses', 'vehicle_status': 'Vehicle Status',
        'admins': 'Admins', 'broadcast_sms': 'Broadcast SMS', 'settings': 'Settings',
        'logout': 'Sign out', 'bills': 'Bills', 'more': 'More', 'sign_in': 'Sign in',
        'username': 'Username', 'password': 'Password',
        'default_credentials': 'Default: sagor / sagor123', 'welcome': 'Welcome!',
        'invalid_credentials': 'Invalid credentials.', 'logged_out': 'Logged out.',
        'add_party': 'Add Party', 'edit': 'Edit', 'delete': 'Delete', 'save': 'Save',
        'cancel': 'Cancel', 'search': 'Search...', 'filter': 'Filter', 'export': 'Export CSV',
        'amount': 'Amount', 'description': 'Description', 'type': 'Type', 'due': 'Due',
        'paid': 'Paid', 'total_due': 'Total Due', 'total_paid': 'Total Paid',
        'outstanding': 'Outstanding', 'copy': 'Copy', 'call': 'Call', 'sms_on': 'SMS ON',
        'sms_off': 'SMS OFF', 'send_sms': 'Send SMS', 'backup': 'Backup',
        'language': 'Language', 'english': 'English', 'bangla': 'Bangla',
        'update': 'Update', 'leave_blank': 'leave blank', 'new_username': 'New Username',
        'new_password': 'New Password', 'confirm_password': 'Confirm Password',
        'current_password': 'Current Password', 'change_profile': 'Change Profile',
        'download_backup': 'Download Backup', 'backup_desc': 'Download database and uploaded files as ZIP.',
        'select_language': 'Select Language',
        'all': 'All', 'has_dues': 'Has dues', 'cleared': 'Cleared', 'name': 'Name',
        'phone': 'Phone', 'vehicle': 'Vehicle', 'balance': 'Balance', 'action': 'Action',
        'view': 'View', 'history': 'History', 'on': 'ON', 'off': 'OFF',
        'running': 'Running', 'stopped': 'Stopped', 'unknown': 'Unknown',
        'documents': 'Documents', 'front': 'Front', 'back': 'Back',
        'no_transactions': 'No transactions yet.',
        'no_parties': 'No customers found.',
        'add_new_customer': 'Add New Customer',
        'edit_customer': 'Edit Customer',
        'customer_details': 'Customer Details',
        'personal_info': 'Personal Info',
        'vehicle_info': 'Vehicle Info',
        'notes': 'Notes',
        'profile_picture': 'Profile Picture',
        'nid_front': 'NID Front',
        'nid_back': 'NID Back',
        'vehicle_number': 'Vehicle Number',
        'vehicle_model': 'Vehicle Model',
        'email': 'Email',
        'address': 'Address',
        'send_to_all': 'Send to All',
        'message': 'Message',
        'simulated': 'SMS sending is simulated.',
        'expense_add': 'Add Expense',
        'expense_edit': 'Edit Expense',
        'date_time': 'Date & Time',
        'no_expenses': 'No expenses recorded yet.',
        'status': 'Status',
        'prev': 'Prev',
        'next': 'Next',
        'page': 'Page',
    },
    'bn': {
        'home': 'হোম', 'transactions': 'লেনদেন', 'parties': 'পার্টি',
        'garage_expenses': 'গ্যারেজ খরচ', 'vehicle_status': 'যানবাহনের অবস্থা',
        'admins': 'অ্যাডমিন', 'broadcast_sms': 'সবাইকে SMS', 'settings': 'সেটিংস',
        'logout': 'সাইন আউট', 'bills': 'বিল', 'more': 'আরও',
        'sign_in': 'সাইন ইন', 'username': 'ইউজারনেম', 'password': 'পাসওয়ার্ড',
        'default_credentials': 'ডিফল্ট: admin / admin123', 'welcome': 'স্বাগতম!',
        'invalid_credentials': 'ভুল তথ্য।', 'logged_out': 'সাইন আউট হয়েছে।',
        'add_party': 'পার্টি যোগ করুন', 'edit': 'সম্পাদনা', 'delete': 'মুছুন',
        'save': 'সংরক্ষণ', 'cancel': 'বাতিল', 'search': 'খুঁজুন...',
        'filter': 'ফিল্টার', 'export': 'CSV এক্সপোর্ট', 'amount': 'পরিমাণ',
        'description': 'বিবরণ', 'type': 'ধরন', 'due': 'বাকি', 'paid': 'পরিশোধ',
        'total_due': 'মোট বাকি', 'total_paid': 'মোট পরিশোধ', 'outstanding': 'বকেয়া',
        'copy': 'কপি', 'call': 'কল', 'sms_on': 'SMS চালু', 'sms_off': 'SMS বন্ধ',
        'send_sms': 'SMS পাঠান', 'backup': 'ব্যাকআপ', 'language': 'ভাষা',
        'english': 'ইংরেজি', 'bangla': 'বাংলা', 'update': 'আপডেট',
        'leave_blank': 'খালি রাখুন', 'new_username': 'নতুন ইউজারনেম',
        'new_password': 'নতুন পাসওয়ার্ড', 'confirm_password': 'পাসওয়ার্ড নিশ্চিত করুন',
        'current_password': 'বর্তমান পাসওয়ার্ড', 'change_profile': 'প্রোফাইল পরিবর্তন',
        'download_backup': 'ব্যাকআপ ডাউনলোড',
        'backup_desc': 'ডাটাবেজ ও আপলোড করা ফাইল জিপ হিসেবে ডাউনলোড করুন।',
        'select_language': 'ভাষা নির্বাচন করুন',
        'all': 'সব', 'has_dues': 'বাকি আছে', 'cleared': 'পরিশোধিত',
        'name': 'নাম', 'phone': 'ফোন', 'vehicle': 'যানবাহন', 'balance': 'ব্যালেন্স',
        'action': 'অ্যাকশন', 'view': 'দেখুন', 'history': 'ইতিহাস',
        'on': 'চালু', 'off': 'বন্ধ', 'running': 'চলছে', 'stopped': 'বন্ধ',
        'unknown': 'অজানা', 'documents': 'ডকুমেন্টস', 'front': 'সামনে',
        'back': 'পেছনে', 'no_transactions': 'এখনো কোনো লেনদেন নেই।',
        'no_parties': 'কোনো গ্রাহক পাওয়া যায়নি।',
        'add_new_customer': 'নতুন গ্রাহক যোগ করুন',
        'edit_customer': 'গ্রাহক সম্পাদনা',
        'customer_details': 'গ্রাহকের বিবরণ',
        'personal_info': 'ব্যক্তিগত তথ্য',
        'vehicle_info': 'যানবাহনের তথ্য',
        'notes': 'নোট',
        'profile_picture': 'প্রোফাইল ছবি',
        'nid_front': 'এনআইডি সামনে',
        'nid_back': 'এনআইডি পেছনে',
        'vehicle_number': 'যানবাহনের নম্বর',
        'vehicle_model': 'যানবাহনের মডেল',
        'email': 'ইমেইল',
        'address': 'ঠিকানা',
        'send_to_all': 'সবাইকে পাঠান',
        'message': 'বার্তা',
        'simulated': 'SMS পাঠানো সিমুলেটেড।',
        'expense_add': 'খরচ যোগ করুন',
        'expense_edit': 'খরচ সম্পাদনা',
        'date_time': 'তারিখ ও সময়',
        'no_expenses': 'এখনো কোনো খরচ রেকর্ড করা হয়নি।',
        'status': 'অবস্থা',
        'prev': 'পূর্ববর্তী',
        'next': 'পরবর্তী',
        'page': 'পৃষ্ঠা',
    }
}

def get_translator(lang):
    def t(key, default=''):
        return translations.get(lang, translations['en']).get(key, default or key)
    return t

@app.context_processor
def inject_globals():
    lang = 'en'
    if 'admin_id' in session:
        admin = db.session.get(Admin, session['admin_id'])
        if admin:
            lang = admin.language
    t = get_translator(lang)
    return dict(now=datetime.now(), permissions=get_current_permissions(), t=t, lang=lang)

# ---------- Init DB ----------
with app.app_context():
    db.create_all()
    if not Admin.query.filter_by(username='admin').first():
        admin = Admin(username='admin', password=generate_password_hash('admin123'),
                      role='admin', permissions=json.dumps({'all': True}), is_active=True)
        db.session.add(admin)
        db.session.commit()

# ---------- Routes ----------
@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'admin_id' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        admin = Admin.query.filter_by(username=username, is_active=True).first()
        if admin and check_password_hash(admin.password, password):
            session.update({'admin_id': admin.id, 'admin_username': admin.username, 'admin_role': admin.role})
            admin.last_login = datetime.now(timezone.utc)
            db.session.commit()
            log_activity('Login')
            flash(get_translator(admin.language)('welcome'), 'success')
            return redirect(url_for('dashboard'))
        flash(get_translator('en')('invalid_credentials'), 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash(get_translator('en')('logged_out'), 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    total_parties = Party.query.filter_by(is_active=True).count()
    total_outstanding = db.session.query(func.sum(Party.total_due - Party.total_paid)).filter(Party.is_active==True).scalar() or 0
    month_start = datetime(datetime.now().year, datetime.now().month, 1)
    month_collections = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.transaction_type=='payment', Transaction.date >= month_start).scalar() or 0
    today_val = date.today()
    today_collections = db.session.query(func.sum(Transaction.amount)).filter(
        Transaction.transaction_type=='payment', func.date(Transaction.date)==today_val).scalar() or 0
    recent = Transaction.query.order_by(Transaction.date.desc()).limit(10).all()
    top_due = Party.query.filter(Party.is_active==True, Party.total_due > Party.total_paid).order_by(
        (Party.total_due - Party.total_paid).desc()).limit(5).all()
    chart_data = []
    for i in range(5, -1, -1):
        d = datetime.now().replace(day=1) - timedelta(days=30*i)
        start = d.replace(day=1)
        end = (d.replace(year=d.year+1, month=1, day=1) if d.month==12 else d.replace(month=d.month+1, day=1))
        amt = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.transaction_type=='payment', Transaction.date >= start, Transaction.date < end).scalar() or 0
        chart_data.append({'month': d.strftime('%b'), 'amount': amt})
    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(8).all()
    return render_template('dashboard.html', total_parties=total_parties, total_outstanding=total_outstanding,
                           month_collections=month_collections, today_collections=today_collections,
                           recent_transactions=recent, top_due_parties=top_due, chart_data=chart_data, activities=activities)

@app.route('/parties')
@login_required
def parties():
    q = request.args.get('q', '').strip()
    filter_type = request.args.get('filter', 'all')
    sort = request.args.get('sort', 'name')
    query = Party.query.filter_by(is_active=True)
    if q:
        query = query.filter(or_(Party.name.contains(q), Party.phone.contains(q), Party.id.contains(q), Party.vehicle_number.contains(q)))
    if filter_type == 'due':
        query = query.filter(Party.total_due > Party.total_paid)
    elif filter_type == 'paid':
        query = query.filter(Party.total_due <= Party.total_paid)
    if sort == 'name':
        query = query.order_by(Party.name)
    elif sort == 'due_desc':
        query = query.order_by((Party.total_due - Party.total_paid).desc())
    elif sort == 'recent':
        query = query.order_by(Party.created_at.desc())
    parties_list = query.all()
    return render_template('parties.html', parties=parties_list, q=q, filter_type=filter_type, sort=sort)

@app.route('/party/add', methods=['GET', 'POST'])
@login_required
def add_party():
    if request.method == 'POST':
        phone = request.form['phone'].strip()
        if Party.query.filter_by(phone=phone).first():
            flash('Phone number already exists.', 'error')
            return render_template('party_form.html', party=None)
        try:
            party = Party(
                id=generate_party_id(),
                name=request.form['name'].strip(),
                phone=phone,
                email=request.form.get('email', '').strip(),
                address=request.form.get('address', '').strip(),
                vehicle_number=request.form.get('vehicle_number', '').strip(),
                vehicle_model=request.form.get('vehicle_model', '').strip(),
                notes=request.form.get('notes', '').strip()
            )
            for field, subdir in [('profile_pic', 'profiles'), ('nid_front', 'nid'), ('nid_back', 'nid')]:
                file = request.files.get(field)
                if file and file.filename and allowed_file(file.filename):
                    fname = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], subdir, fname))
                    setattr(party, field, f'uploads/{subdir}/{fname}')
            db.session.add(party)
            db.session.commit()
            log_activity('Party created', party.name)
            flash('Customer added!', 'success')
            return redirect(url_for('party_detail', party_id=party.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('party_form.html', party=None)

@app.route('/party/<party_id>')
@login_required
def party_detail(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Customer not found.', 'error')
        return redirect(url_for('parties'))
    trans = Transaction.query.filter_by(party_id=party_id).order_by(Transaction.date.desc()).all()
    total_due = sum(t.amount for t in trans if t.transaction_type=='due')
    total_paid = sum(t.amount for t in trans if t.transaction_type=='payment')
    return render_template('party_detail.html', party=party, transactions=trans,
                           total_due=total_due, total_paid=total_paid, current_due=total_due-total_paid)

@app.route('/party/<party_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_party(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Customer not found.', 'error')
        return redirect(url_for('parties'))
    if request.method == 'POST':
        new_phone = request.form['phone'].strip()
        if Party.query.filter(Party.phone==new_phone, Party.id!=party_id).first():
            flash('Phone already used.', 'error')
            return render_template('party_form.html', party=party)
        try:
            party.name = request.form['name'].strip()
            party.phone = new_phone
            party.email = request.form.get('email', '').strip()
            party.address = request.form.get('address', '').strip()
            party.vehicle_number = request.form.get('vehicle_number', '').strip()
            party.vehicle_model = request.form.get('vehicle_model', '').strip()
            party.notes = request.form.get('notes', '').strip()
            for field, subdir in [('profile_pic', 'profiles'), ('nid_front', 'nid'), ('nid_back', 'nid')]:
                file = request.files.get(field)
                if file and file.filename and allowed_file(file.filename):
                    old = getattr(party, field)
                    if old and os.path.exists(os.path.join('static', old)):
                        os.remove(os.path.join('static', old))
                    fname = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], subdir, fname))
                    setattr(party, field, f'uploads/{subdir}/{fname}')
            db.session.commit()
            log_activity('Party updated', party.name)
            flash('Customer updated.', 'success')
            return redirect(url_for('party_detail', party_id=party.id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'error')
    return render_template('party_form.html', party=party)

@app.route('/party/<party_id>/delete', methods=['POST'])
@login_required
@permission_required('can_delete_data')
def delete_party(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Customer not found.', 'error')
        return redirect(url_for('parties'))
    for attr in ['profile_pic', 'nid_front', 'nid_back']:
        path = getattr(party, attr)
        if path and os.path.exists(os.path.join('static', path)):
            os.remove(os.path.join('static', path))
    db.session.delete(party)
    db.session.commit()
    log_activity('Party deleted', party.name)
    flash('Customer deleted.', 'success')
    return redirect(url_for('parties'))

# Transactions route (unchanged)
@app.route('/transaction/add/<party_id>', methods=['POST'])
@login_required
def add_transaction(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Customer not found.', 'error')
        return redirect(url_for('parties'))
    try:
        amount = float(request.form['amount'])
        if amount <= 0:
            flash('Amount must be positive.', 'error')
            return redirect(url_for('party_detail', party_id=party_id))
        ttype = request.form['transaction_type']
        trans = Transaction(
            party_id=party_id, amount=amount, transaction_type=ttype,
            description=request.form.get('description', '').strip(),
            payment_method=request.form.get('payment_method', 'cash').strip(),
            bill_number=generate_bill_number(),
            created_by=session.get('admin_id')
        )
        if ttype == 'due':
            party.total_due += amount
        else:
            party.total_paid += amount
        db.session.add(trans)
        db.session.commit()
        log_activity('Transaction', f'{ttype} Tk {amount} for {party.name}')
        flash('Transaction added.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'error')
    return redirect(url_for('party_detail', party_id=party_id))

@app.route('/transactions')
@login_required
def all_transactions():
    page = request.args.get('page', 1, type=int)
    ttype = request.args.get('type', 'all')
    query = Transaction.query
    if ttype != 'all':
        query = query.filter_by(transaction_type=ttype)
    trans = query.order_by(Transaction.date.desc()).paginate(page=page, per_page=50)
    return render_template('transactions.html', transactions=trans, ttype=ttype)

# Garage transactions (unchanged)
@app.route('/garage-transactions')
@login_required
def garage_transactions():
    page = request.args.get('page', 1, type=int)
    gtrans = GarageTransaction.query.order_by(GarageTransaction.date.desc()).paginate(page=page, per_page=50)
    return render_template('garage_transactions.html', transactions=gtrans)

@app.route('/garage-transaction/add', methods=['POST'])
@login_required
def add_garage_transaction():
    description = request.form.get('description', '').strip()
    amount = float(request.form.get('amount', 0))
    if not description or amount <= 0:
        flash('Invalid input.', 'error')
        return redirect(url_for('garage_transactions'))
    gt = GarageTransaction(description=description, amount=amount, created_by=session.get('admin_id'))
    db.session.add(gt)
    db.session.commit()
    flash('Expense added.', 'success')
    return redirect(url_for('garage_transactions'))

@app.route('/garage-transaction/<int:gt_id>/edit', methods=['POST'])
@login_required
def edit_garage_transaction(gt_id):
    gt = db.session.get(GarageTransaction, gt_id)
    if not gt:
        flash('Transaction not found.', 'error')
        return redirect(url_for('garage_transactions'))
    gt.description = request.form.get('description', '').strip()
    gt.amount = float(request.form.get('amount', 0))
    db.session.commit()
    flash('Expense updated.', 'success')
    return redirect(url_for('garage_transactions'))

# Vehicle status (unchanged)
@app.route('/vehicles')
@login_required
def vehicle_status():
    q = request.args.get('q', '').strip()
    filter_stat = request.args.get('status', 'all')
    query = Party.query.filter(Party.is_active==True, Party.vehicle_number!='')
    if q:
        query = query.filter(or_(Party.name.contains(q), Party.vehicle_number.contains(q), Party.id.contains(q)))
    if filter_stat == 'on':
        sub = db.session.query(VehicleStatus.party_id, func.max(VehicleStatus.timestamp).label('max_ts')).group_by(VehicleStatus.party_id).subquery()
        query = query.join(sub, Party.id==sub.c.party_id).join(VehicleStatus, db.and_(VehicleStatus.party_id==sub.c.party_id, VehicleStatus.timestamp==sub.c.max_ts)).filter(VehicleStatus.status=='ON')
    elif filter_stat == 'off':
        sub = db.session.query(VehicleStatus.party_id, func.max(VehicleStatus.timestamp).label('max_ts')).group_by(VehicleStatus.party_id).subquery()
        query = query.join(sub, Party.id==sub.c.party_id).join(VehicleStatus, db.and_(VehicleStatus.party_id==sub.c.party_id, VehicleStatus.timestamp==sub.c.max_ts)).filter(VehicleStatus.status=='OFF')
    parties_list = query.order_by(Party.name).all()
    return render_template('vehicle_status.html', parties=parties_list, q=q, filter_status=filter_stat)

@app.route('/vehicle/<party_id>/status', methods=['POST'])
@login_required
def update_vehicle_status(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Party not found.', 'error')
        return redirect(url_for('vehicle_status'))
    new_status = request.form.get('status')
    if new_status not in ('ON', 'OFF'):
        flash('Invalid status.', 'error')
        return redirect(url_for('vehicle_status'))
    vs = VehicleStatus(party_id=party_id, status=new_status, created_by=session.get('admin_id'))
    db.session.add(vs)
    db.session.commit()
    if party.sms_enabled:
        message = f"Dear {party.name}, your vehicle {party.vehicle_number} is now {new_status}."
        success = send_sms(party.phone, message)
        sms_log = SmsLog(party_id=party_id, phone=party.phone, message=message, status='sent' if success else 'failed')
        db.session.add(sms_log)
        db.session.commit()
    flash(f'Vehicle status updated to {new_status}.', 'success')
    return redirect(url_for('vehicle_status'))

@app.route('/vehicle/<party_id>/history')
@login_required
def vehicle_history(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Party not found.', 'error')
        return redirect(url_for('vehicle_status'))
    statuses = VehicleStatus.query.filter_by(party_id=party_id).order_by(VehicleStatus.timestamp.asc()).all()
    total_on = timedelta()
    total_off = timedelta()
    prev_time = None
    prev_status = None
    for s in statuses:
        if prev_time and prev_status:
            diff = s.timestamp - prev_time
            if prev_status == 'ON':
                total_on += diff
            else:
                total_off += diff
        prev_time = s.timestamp
        prev_status = s.status
    return render_template('vehicle_history.html', party=party, statuses=statuses, total_on=total_on, total_off=total_off)

# SMS
@app.route('/broadcast-sms', methods=['GET', 'POST'])
@login_required
@admin_required
def broadcast_sms():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        if not message:
            flash('Message required.', 'error')
            return redirect(url_for('broadcast_sms'))
        parties = Party.query.filter_by(is_active=True).all()
        success_count = 0
        for p in parties:
            if send_sms(p.phone, message):
                success_count += 1
                log = SmsLog(party_id=p.id, phone=p.phone, message=message, status='sent')
            else:
                log = SmsLog(party_id=p.id, phone=p.phone, message=message, status='failed')
            db.session.add(log)
        db.session.commit()
        flash(f'SMS sent to {success_count}/{len(parties)} parties.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('broadcast_sms.html')

@app.route('/party/<party_id>/toggle-sms', methods=['GET', 'POST'])
@login_required
def toggle_sms(party_id):
    party = db.session.get(Party, party_id)
    if not party:
        flash('Customer not found.', 'error')
        return redirect(url_for('parties'))
    party.sms_enabled = not party.sms_enabled
    db.session.commit()
    flash(f'SMS {"enabled" if party.sms_enabled else "disabled"} for {party.name}.', 'success')
    return redirect(request.referrer or url_for('parties'))

# Admins
@app.route('/admins')
@login_required
@admin_required
def manage_admins():
    admins = Admin.query.all()
    return render_template('admins.html', admins=admins)

@app.route('/admin/add', methods=['POST'])
@login_required
@admin_required
def add_admin():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        flash('Username and password are required.', 'error')
        return redirect(url_for('manage_admins'))
    
    if len(password) < 4:
        flash('Password must be at least 4 characters.', 'error')
        return redirect(url_for('manage_admins'))
    
    if Admin.query.filter_by(username=username).first():
        flash('Username already exists.', 'error')
        return redirect(url_for('manage_admins'))
    
    perms = {
        'can_manage_users': request.form.get('perm_users') == 'on',
        'can_manage_transactions': request.form.get('perm_transactions') == 'on',
        'can_manage_media': request.form.get('perm_media') == 'on',
        'can_manage_settings': request.form.get('perm_settings') == 'on',
        'can_export_data': request.form.get('perm_export') == 'on',
        'can_delete_data': request.form.get('perm_delete') == 'on'
    }
    
    try:
        admin = Admin(
            username=username,
            password=generate_password_hash(password),
            role='moderator',
            permissions=json.dumps(perms),
            created_by=session['admin_id']
        )
        db.session.add(admin)
        db.session.commit()
        log_activity('Admin created', f'Moderator: {username}')
        flash('Moderator account created successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating account: {str(e)}', 'error')
    
    return redirect(url_for('manage_admins'))

@app.route('/admin/<int:admin_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_admin(admin_id):
    admin = db.session.get(Admin, admin_id)
    if not admin or admin.id == session['admin_id']:
        flash('Cannot delete.', 'error')
        return redirect(url_for('manage_admins'))
    db.session.delete(admin)
    db.session.commit()
    flash('Account deleted.', 'success')
    return redirect(url_for('manage_admins'))

# Settings
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    admin = db.session.get(Admin, session['admin_id'])
    if request.method == 'POST':
        if 'language' in request.form:
            lang = request.form['language']
            if lang in ('en', 'bn'):
                admin.language = lang
                db.session.commit()
                flash(get_translator(lang)('language_updated'), 'success')
                return redirect(url_for('settings'))
        if not check_password_hash(admin.password, request.form['current_password']):
            flash(get_translator(admin.language)('current_password_incorrect'), 'error')
        else:
            if request.form.get('new_username'):
                new_username = request.form['new_username'].strip()
                if Admin.query.filter(Admin.username==new_username, Admin.id!=admin.id).first():
                    flash(get_translator(admin.language)('username_taken'), 'error')
                    return redirect(url_for('settings'))
                admin.username = new_username
                session['admin_username'] = admin.username
            if request.form.get('new_password'):
                if request.form['new_password'] != request.form.get('confirm_password'):
                    flash(get_translator(admin.language)('passwords_mismatch'), 'error')
                    return redirect(url_for('settings'))
                admin.password = generate_password_hash(request.form['new_password'])
            db.session.commit()
            flash(get_translator(admin.language)('settings_updated'), 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', admin=admin, lang=admin.language)

# Backup
@app.route('/download-backup')
@login_required
def download_backup():
    mem_zip = io.BytesIO()
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        db_path = 'garage.db'
        if os.path.exists(db_path):
            zf.write(db_path, 'garage.db')
        uploads_dir = app.config['UPLOAD_FOLDER']
        for root, dirs, files in os.walk(uploads_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, start=uploads_dir)
                zf.write(file_path, os.path.join('uploads', arcname))
    mem_zip.seek(0)
    return send_file(mem_zip, download_name=f'garagepro_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip', as_attachment=True)

# Export
@app.route('/export/parties')
@login_required
def export_parties():
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['ID','Name','Phone','Email','Vehicle','Total Due','Total Paid','Outstanding'])
    for p in Party.query.all():
        cw.writerow([p.id, p.name, p.phone, p.email, p.vehicle_number, p.total_due, p.total_paid, p.total_due-p.total_paid])
    return Response(si.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=parties.csv'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)