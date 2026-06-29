from flask import Flask, render_template, request, send_file, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
from nudenet import NudeDetector
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from PyPDF2 import PdfWriter, PdfReader
import cv2

# Lazy import DeepFace to avoid TensorFlow initialization issues
try:
    from deepface import DeepFace
    DEEPFACE_AVAILABLE = True
except (ImportError, ModuleNotFoundError) as e:
    print(f"WARNING: DeepFace not available: {e}")
    DEEPFACE_AVAILABLE = False
    DeepFace = None
import numpy as np
import hashlib
import time
import smtplib
import secrets
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl
import logging
import hmac
import json
import re
from pathlib import Path
from functools import wraps
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv(Path(__file__).resolve().parent / '.env')

def env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')

app = Flask(__name__)

# ============= DATABASE CONFIGURATION =============
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///herlens.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ============= APPLICATION SECRETS & SETTINGS =============
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'change-me-in-production')
TIMESTAMP_SECRET = os.getenv('TIMESTAMP_SECRET', '')
APP_BASE_URL = os.getenv('APP_BASE_URL', 'http://127.0.0.1:5000').rstrip('/')

SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SENDER_EMAIL = os.getenv('SENDER_EMAIL', '')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD', '')
TESTING_MODE = env_bool('TESTING_MODE', False)
ENABLE_DEBUG_ROUTES = env_bool('ENABLE_DEBUG_ROUTES', False)
ADMIN_ACCESS_KEY = os.getenv('ADMIN_ACCESS_KEY', '')
MAX_UPLOAD_BYTES = int(os.getenv('MAX_UPLOAD_MB', '16')) * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'}
WEAK_SECRET_VALUES = {
    '',
    'change-me-in-production',
    'herlens-secret-key-2024',
    'HerLens-Crypto-Secret-Key-2024',
}

app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_BYTES
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
if not env_bool('FLASK_DEBUG', True):
    app.config['SESSION_COOKIE_SECURE'] = True

# ============= DATABASE MODELS =============
class User(db.Model):
    """Store user information"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    total_analyses = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    analyses = db.relationship('Analysis', backref='user', lazy=True)

class Analysis(db.Model):
    """Store each analysis result"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    file_size = db.Column(db.Float, nullable=False)
    image_dimensions = db.Column(db.String(50))
    
    # Detection results
    explicit_detected = db.Column(db.Boolean, default=False)
    explicit_confidence = db.Column(db.Float, default=0.0)
    deepfake_detected = db.Column(db.Boolean, default=False)
    deepfake_confidence = db.Column(db.Float, default=0.0)
    
    # Risk assessment
    risk_level = db.Column(db.String(20))
    action_taken = db.Column(db.String(200))
    
    # Report info
    pdf_password = db.Column(db.String(50))
    pdf_path = db.Column(db.String(200))
    email_sent = db.Column(db.Boolean, default=False)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processing_time = db.Column(db.Float)
    
    # ===== NEW: Cryptographic timestamp fields =====
    crypto_timestamp = db.Column(db.String(500))  # Store the full timestamp data
    timestamp_hash = db.Column(db.String(64))     # Hash of the results
    timestamp_signature = db.Column(db.String(200)) # Digital signature

# Create database tables
with app.app_context():
    db.create_all()
    print("✅ Database initialized!")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Folders
STATIC_UPLOAD_FOLDER = os.path.join('static', 'uploads')
PDF_REPORT_FOLDER = 'uploads'

os.makedirs(STATIC_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PDF_REPORT_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = PDF_REPORT_FOLDER

def validate_security_settings():
    """Block insecure defaults outside local development."""
    if env_bool('FLASK_DEBUG', True):
        return
    if app.config['SECRET_KEY'] in WEAK_SECRET_VALUES:
        raise RuntimeError('Set a strong FLASK_SECRET_KEY in .env before running in production.')
    if TIMESTAMP_SECRET in WEAK_SECRET_VALUES:
        raise RuntimeError('Set a strong TIMESTAMP_SECRET in .env before running in production.')
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        raise RuntimeError('Set SENDER_EMAIL and SENDER_PASSWORD in .env before running in production.')

validate_security_settings()

def is_local_request():
    return request.remote_addr in ('127.0.0.1', '::1')

def require_local_or_admin():
    if is_local_request():
        return True
    if ADMIN_ACCESS_KEY and constant_time_compare(
        request.args.get('access_key', ''),
        ADMIN_ACCESS_KEY,
    ):
        return True
    return False

def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not require_local_or_admin():
            abort(403)
        return view(*args, **kwargs)
    return wrapped

def debug_only(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not ENABLE_DEBUG_ROUTES:
            abort(404)
        return view(*args, **kwargs)
    return wrapped

def is_valid_email(email):
    if not email or len(email) > 254:
        return False
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def safe_report_path(filename):
    safe_name = secure_filename(filename)
    if not safe_name:
        return None
    base_dir = os.path.abspath(PDF_REPORT_FOLDER)
    report_path = os.path.abspath(os.path.join(PDF_REPORT_FOLDER, safe_name))
    try:
        if os.path.commonpath([base_dir, report_path]) != base_dir:
            return None
    except ValueError:
        return None
    return report_path

def generate_download_token(analysis_id, pdf_filename):
    return hmac.new(
        app.config['SECRET_KEY'].encode(),
        f'{analysis_id}:{pdf_filename}'.encode(),
        hashlib.sha256,
    ).hexdigest()

def verify_download_token(analysis_id, pdf_filename, token):
    if not token:
        return False
    expected = generate_download_token(analysis_id, pdf_filename)
    return constant_time_compare(expected, token)

def build_download_url(analysis_id, pdf_filename):
    token = generate_download_token(analysis_id, pdf_filename)
    return url_for('download_report', filename=pdf_filename, token=token)

def create_stored_upload_filename(original_filename):
    extension = os.path.splitext(secure_filename(original_filename))[1].lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValueError('Unsupported file type')
    return f'{secrets.token_hex(16)}{extension}'

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response

@app.context_processor
def inject_template_helpers():
    return {'download_url': build_download_url}

@app.template_filter('signed_download_url')
def signed_download_url(analysis):
    if not analysis or not analysis.pdf_path:
        return '#'
    return build_download_url(analysis.id, analysis.pdf_path)

# Initialize NudeNet detector
detector = NudeDetector()

# ============= EXPANDED UNSAFE CATEGORIES =============
UNSAFE_CATEGORIES = [
    # Explicit content (original)
    'FEMALE_BREAST_EXPOSED',
    'MALE_BREAST_EXPOSED',
    'BUTTOCKS_EXPOSED',
    'ANUS_EXPOSED',
    'FEMALE_GENITALIA_EXPOSED',
    'MALE_GENITALIA_EXPOSED',
    'ARMPITS_EXPOSED',
    'BELLY_EXPOSED',
    
    # Additional categories for better detection
    'FEMALE_BREAST_COVERED',
    'BUTTOCKS_COVERED',
    'FEMALE_GENITALIA_COVERED',
    'MALE_GENITALIA_COVERED',
    'LINGERIE',
    'SWIMSUIT',
    'UNDERWEAR',
    'BIKINI',
    'CLEAVAGE',
    'NIPPLE',
    'PUBIC_HAIR',
    'BUTTOCKS',
    'BREAST',
    'GENITALIA'
]

# ============= CRYPTOGRAPHIC TIMESTAMP FUNCTIONS =============
def create_crypto_timestamp(analysis_data):
    """
    Create a cryptographic timestamp for analysis results
    """
    # 1. Get current UTC time
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # 2. Create data package
    data_package = {
        'timestamp': timestamp,
        'analysis_id': analysis_data.get('analysis_id', ''),
        'filename': analysis_data['filename'],
        'explicit_confidence': analysis_data['explicit_confidence'],
        'deepfake_confidence': analysis_data['deepfake_confidence'],
        'risk_level': analysis_data['risk_level'],
        'user_email': analysis_data['user_email'],
        'app_version': 'HerLens v1.0'
    }
    
    # 3. Convert to JSON string
    json_string = json.dumps(data_package, sort_keys=True)
    
    # 4. Create hash of the data
    data_hash = hashlib.sha256(json_string.encode()).hexdigest()
    
    # 5. Create HMAC signature (proves it came from your server)
    signature = hmac.new(
        TIMESTAMP_SECRET.encode(),
        json_string.encode(),
        hashlib.sha256
    ).hexdigest()
    
    # 6. Combine everything
    crypto_timestamp = {
        'data': data_package,
        'hash': data_hash,
        'signature': signature,
        'verification_url': '/verify-timestamp'
    }
    
    return crypto_timestamp, json_string

def constant_time_compare(a, b):
    """Compare two strings in constant time to prevent timing attacks"""
    return hmac.compare_digest(str(a).encode(), str(b).encode())

def normalize_crypto_input(value):
    """Normalize hash/signature pasted from PDF reports."""
    if not value:
        return ''
    return value.strip().lower().replace(' ', '')

def verify_crypto_package(crypto_timestamp):
    """
    Verify hash and HMAC signature against the signed data package.
    Uses the stored data payload — not live database fields.
    """
    if not crypto_timestamp or 'data' not in crypto_timestamp:
        return False, False, '', ''

    data_package = crypto_timestamp['data']
    json_string = json.dumps(data_package, sort_keys=True)
    calculated_hash = hashlib.sha256(json_string.encode()).hexdigest()
    calculated_signature = hmac.new(
        TIMESTAMP_SECRET.encode(),
        json_string.encode(),
        hashlib.sha256
    ).hexdigest()

    hash_valid = constant_time_compare(calculated_hash, crypto_timestamp.get('hash', ''))
    signature_valid = constant_time_compare(
        calculated_signature,
        crypto_timestamp.get('signature', '')
    )
    return hash_valid, signature_valid, calculated_hash, calculated_signature

def signed_data_matches_analysis(analysis, signed_data):
    """Check whether the database record still matches the signed payload."""
    if not signed_data:
        return False

    def values_match(signed_value, current_value):
        if isinstance(signed_value, (int, float)) or isinstance(current_value, (int, float)):
            return float(signed_value) == float(current_value)
        return str(signed_value) == str(current_value)

    checks = {
        'analysis_id': analysis.id,
        'filename': analysis.filename,
        'explicit_confidence': analysis.explicit_confidence,
        'deepfake_confidence': analysis.deepfake_confidence,
        'risk_level': analysis.risk_level,
        'user_email': analysis.user.email,
    }

    return all(
        values_match(signed_data.get(field), current_value)
        for field, current_value in checks.items()
    )

# ============= PASSWORD GENERATION FUNCTION =============
def generate_random_password(length=12):
    """Generate a cryptographically secure random password for PDF"""
    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(characters) for _ in range(length))

# ============= EMAIL SENDING FUNCTION =============
def send_password_email(recipient_email, password, filename, risk_level):
    """
    Send email with PDF password to ANY email address
    """
    if TESTING_MODE:
        logger.info("TEST MODE - Email would be sent to: %s (password redacted)", recipient_email)
        return True
    
    try:
        logger.info(f"Preparing email for recipient")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"HerLens <{SENDER_EMAIL}>"
        msg['To'] = recipient_email
        msg['Subject'] = "🔐 HerLens - Your PDF Report Password"
        
        # Plain text version
        text_body = f"""
        HERLENS - Your PDF Report Password
        
        File: {filename}
        Risk Level: {risk_level}
        
        Your PDF password is: {password}
        
        Instructions:
        1. Download your report from the HerLens website
        2. Open the PDF file
        3. Enter this password when prompted
        
        - HerLens AI Team
        """
        
        # HTML version
        html_body = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    background: #0a0a0a;
                    margin: 0;
                    padding: 30px 20px;
                }}
                .container {{
                    max-width: 550px;
                    margin: 0 auto;
                    background: linear-gradient(145deg, #111, #1c1c1c);
                    border-radius: 25px;
                    padding: 35px;
                    border: 2px solid #c399ff;
                    box-shadow: 0 0 40px rgba(195, 153, 255, 0.3);
                }}
                h1 {{
                    font-family: 'Orbitron', sans-serif;
                    color: #c399ff;
                    text-align: center;
                    font-size: 36px;
                    margin: 0 0 10px 0;
                    text-shadow: 0 0 15px #c399ff;
                }}
                .subtitle {{
                    text-align: center;
                    color: #888;
                    font-size: 14px;
                    margin-bottom: 30px;
                }}
                .info-box {{
                    background: rgba(195, 153, 255, 0.1);
                    border-radius: 15px;
                    padding: 20px;
                    margin: 25px 0;
                    border: 1px solid #c399ff;
                }}
                .password-box {{
                    background: #0a0a0a;
                    border: 3px dashed #c399ff;
                    border-radius: 15px;
                    padding: 25px;
                    text-align: center;
                    margin: 30px 0;
                }}
                .password-label {{
                    color: #c399ff;
                    font-size: 14px;
                    margin-bottom: 10px;
                }}
                .password {{
                    font-family: 'Courier New', monospace;
                    font-size: 32px;
                    color: #c399ff;
                    letter-spacing: 5px;
                    background: #111;
                    padding: 15px;
                    border-radius: 10px;
                    border: 1px solid #c399ff;
                }}
                .warning {{
                    background: rgba(255, 107, 107, 0.1);
                    border-left: 4px solid #ff6b6b;
                    padding: 15px;
                    border-radius: 10px;
                    color: #ff6b6b;
                    margin: 25px 0;
                }}
                .footer {{
                    text-align: center;
                    color: #666;
                    font-size: 12px;
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #333;
                }}
                .badge {{
                    display: inline-block;
                    padding: 5px 15px;
                    border-radius: 20px;
                    font-weight: bold;
                    margin-left: 10px;
                }}
                .risk-high {{
                    background: rgba(255, 107, 107, 0.2);
                    color: #ff6b6b;
                    border: 1px solid #ff6b6b;
                }}
                .risk-safe {{
                    background: rgba(76, 175, 80, 0.2);
                    color: #4caf50;
                    border: 1px solid #4caf50;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🛡️ HerLens</h1>
                <div class="subtitle">Your AI-Powered Content Guardian</div>
                
                <div class="info-box">
                    <p style="color: #fff; margin: 5px 0;">
                        <strong style="color: #c399ff;">File:</strong> {filename}
                    </p>
                    <p style="color: #fff; margin: 5px 0;">
                        <strong style="color: #c399ff;">Risk Level:</strong> 
                        <span class="badge {'risk-high' if 'HIGH' in risk_level or 'CRITICAL' in risk_level else 'risk-safe'}">
                            {risk_level}
                        </span>
                    </p>
                </div>
                
                <div class="password-box">
                    <div class="password-label">🔐 Your PDF Password</div>
                    <div class="password">{password}</div>
                </div>
                
                <div class="warning">
                    ⚠️ <strong>Important:</strong> This password is required to open your encrypted PDF report. 
                    Keep it secure and do not share it with anyone.
                </div>
                
                <div style="background: rgba(195,153,255,0.05); border-radius: 10px; padding: 15px;">
                    <p style="color: #888; margin: 0 0 10px 0;">📋 Instructions:</p>
                    <ol style="color: #ccc; margin: 0; padding-left: 20px;">
                        <li>Download your report from the HerLens website</li>
                        <li>Open the PDF file with any PDF reader</li>
                        <li>Enter the password above when prompted</li>
                        <li>View your complete analysis results</li>
                    </ol>
                </div>
                
                <div class="footer">
                    This is an automated message from HerLens AI.<br>
                    "Her Face. Her Identity. No One's Weapon!"<br>
                    © 2024 HerLens - Empowering Women Through Technology
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(text_body, 'plain'))
        msg.attach(MIMEText(html_body, 'html'))
        
        # Connect to Gmail SMTP server
        logger.info("🔌 Connecting to Gmail SMTP server...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=30)
        server.starttls(context=ssl.create_default_context())
        
        # Login with app password
        logger.info("🔑 Logging in...")
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        # Send email
        logger.info("📨 Sending message...")
        server.send_message(msg)
        
        # Close connection
        server.quit()
        
        logger.info(f"✅ Email sent successfully to {recipient_email}")
        return True
        
    except smtplib.SMTPAuthenticationError as e:
        logger.error(f"Authentication failed: {e}")
        logger.error("Check SENDER_EMAIL and SENDER_PASSWORD in your .env file.")
        return False
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        return False

# ============= PDF REPORT GENERATION FUNCTION (UPDATED WITH TIMESTAMP) =============
def generate_report(filepath, filename, detection_results, face_analysis, image_metadata, processing_time, pdf_password, crypto_timestamp=None):
    """
    Generate comprehensive formal report with custom password and cryptographic timestamp
    """
    report_path = os.path.join(PDF_REPORT_FOLDER, f"{filename.replace(' ', '_')}_report.pdf")
    temp_report_path = os.path.join(PDF_REPORT_FOLDER, f"temp_{filename.replace(' ', '_')}_report.pdf")
    
    # Calculate file hash before generating report
    with open(filepath, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    
    # Create document with A4 size and margins
    doc = SimpleDocTemplate(
        temp_report_path,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72
    )
    
    styles = getSampleStyleSheet()
    story = []
    
    # Custom styles for better formatting
    styles.add(ParagraphStyle(
        name='CenterTitle',
        parent=styles['Heading1'],
        alignment=1,
        spaceAfter=30,
        fontSize=24,
        textColor=colors.HexColor('#c399ff'),
        fontName='Helvetica-Bold'
    ))
    
    styles.add(ParagraphStyle(
        name='SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#c399ff'),
        spaceAfter=12,
        spaceBefore=20,
        borderWidth=1,
        borderColor=colors.HexColor('#c399ff'),
        borderPadding=8,
        borderRadius=5,
        fontName='Helvetica-Bold',
        backColor=colors.HexColor('#1a1a1a')
    ))
    
    styles.add(ParagraphStyle(
        name='NormalText',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=6
    ))
    
    styles.add(ParagraphStyle(
        name='ItalicText',
        parent=styles['Italic'],
        fontSize=9,
        textColor=colors.HexColor('#666666'),
        alignment=1,
        spaceAfter=12
    ))
    
    # 1. TITLE
    story.append(Paragraph(
        "HERLENS - AI ANALYSIS REPORT",
        styles['CenterTitle']
    ))
    story.append(Spacer(1, 0.2*inch))
    
    # 2. REPORT METADATA - Beautiful table with proper formatting
    report_id = f"HL-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    metadata_data = [
        ['Report ID:', report_id],
        ['Analysis ID:', str(detection_results.get('analysis_id', 'N/A'))],
        ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ['Analyst:', 'HerLens AI v1.0'],
    ]
    
    metadata_table = Table(metadata_data, colWidths=[1.5*inch, 5*inch])
    metadata_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#c399ff')),  # Purple labels
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),  # Black values
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9f9f9')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f9f9f9'), colors.HexColor('#ffffff')]),
    ]))
    story.append(metadata_table)
    story.append(Spacer(1, 0.2*inch))
    
    # 3. EXECUTIVE SUMMARY
    story.append(Paragraph("EXECUTIVE SUMMARY", styles['SectionHeader']))
    
    # Calculate confidence scores
    explicit_confidence = detection_results.get('explicit_confidence', 0)
    deepfake_confidence = detection_results.get('deepfake_confidence', 0)
    
    summary_text = f"""
    This report presents the findings of automated analysis performed on '{filename}'. 
    The analysis indicates <b>{detection_results['risk_level']}</b> with {explicit_confidence:.1f}% confidence for explicit content 
    and {deepfake_confidence:.1f}% confidence for AI-generated content.
    """
    story.append(Paragraph(summary_text, styles['NormalText']))
    story.append(Spacer(1, 0.2*inch))
    
    # 4. SUBJECT INFORMATION
    story.append(Paragraph("1. SUBJECT INFORMATION", styles['SectionHeader']))
    
    subject_data = [
        ['File Name:', filename],
        ['File Size:', f"{os.path.getsize(filepath) / (1024*1024):.2f} MB"],
        ['Dimensions:', f"{image_metadata.get('width', 'N/A')} x {image_metadata.get('height', 'N/A')}"],
        ['Format:', image_metadata.get('format', 'N/A')],
        ['Confidence Score:', f"{explicit_confidence:.1f}%"],
    ]
    
    subject_table = Table(subject_data, colWidths=[1.5*inch, 5*inch])
    subject_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#c399ff')),  # Purple labels
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),  # Black values
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9f9f9')),
        ('PADDING', (0,0), (-1,-1), 8),
        ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f9f9f9'), colors.HexColor('#ffffff')]),
    ]))
    story.append(subject_table)
    story.append(Spacer(1, 0.2*inch))
    
    # 5. DETECTION RESULTS
    story.append(Paragraph("2. DETECTION RESULTS", styles['SectionHeader']))
    
    results_data = [
        ['Category', 'Status', 'Confidence'],
        ['Explicit Content', 
         '⚠️ DETECTED' if detection_results['explicit_detected'] else '✓ CLEAR',
         f"{explicit_confidence:.1f}%"],
        ['AI-Generated (Deepfake)', 
         '⚠️ DETECTED' if detection_results['deepfake_detected'] else '✓ CLEAR',
         f"{deepfake_confidence:.1f}%"],
    ]
    
    results_table = Table(results_data, colWidths=[2.5*inch, 2*inch, 1.5*inch])
    results_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#c399ff')),
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#c399ff')),  # Purple header
        ('TEXTCOLOR', (0,0), (-1,0), colors.black),  # Black text in header
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f9f9f9')),
        ('PADDING', (0,0), (-1,-1), 10),
        ('FONTSIZE', (0,0), (-1,0), 11),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ]))
    
    # Color code status cells
    if detection_results['explicit_detected']:
        results_table.setStyle(TableStyle([
            ('TEXTCOLOR', (1,1), (1,1), colors.HexColor('#ff6b6b')),
            ('BACKGROUND', (1,1), (1,1), colors.HexColor('#ffeeee')),
        ]))
    else:
        results_table.setStyle(TableStyle([
            ('TEXTCOLOR', (1,1), (1,1), colors.HexColor('#4caf50')),
            ('BACKGROUND', (1,1), (1,1), colors.HexColor('#eeffee')),
        ]))
    
    if detection_results['deepfake_detected']:
        results_table.setStyle(TableStyle([
            ('TEXTCOLOR', (1,2), (1,2), colors.HexColor('#ff6b6b')),
            ('BACKGROUND', (1,2), (1,2), colors.HexColor('#ffeeee')),
        ]))
    else:
        results_table.setStyle(TableStyle([
            ('TEXTCOLOR', (1,2), (1,2), colors.HexColor('#4caf50')),
            ('BACKGROUND', (1,2), (1,2), colors.HexColor('#eeffee')),
        ]))
    
    story.append(results_table)
    story.append(Spacer(1, 0.2*inch))
    
    # ===== NEW: FACE ANALYSIS DETAILS SECTION =====
    # Added right after Detection Results (Section 2) and before Recommendations (Section 3)
    if face_analysis and len(face_analysis) > 0:
        story.append(Paragraph("3. FACE ANALYSIS DETAILS", styles['SectionHeader']))
        
        # Number of faces detected
        face_count = len(face_analysis)
        story.append(Paragraph(f"<b>Faces Detected:</b> {face_count}", styles['NormalText']))
        story.append(Spacer(1, 0.1*inch))
        
        # Details for each face
        for i, face in enumerate(face_analysis):
            # Face header
            story.append(Paragraph(f"<b>Face #{i+1}:</b>", styles['NormalText']))
            
            # Face details in a table
            face_details = [
                ['Age:', str(face.get('age', 'N/A'))],
                ['Gender:', f"{face.get('gender', 'Unknown')} ({face.get('gender_confidence', 0):.1f}%)"],
                ['Emotion:', face.get('dominant_emotion', 'neutral')],
                ['Is Real:', str(face.get('is_real', 'N/A'))],
                ['Anti-spoof Score:', f"{face.get('antispoof_score', 0):.4f}"],
            ]
            
            face_table = Table(face_details, colWidths=[1.5*inch, 4.5*inch])
            face_table.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#c399ff')),  # Purple labels
                ('TEXTCOLOR', (1,0), (1,-1), colors.black),  # Black values
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
                ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9f9f9')),
                ('PADDING', (0,0), (-1,-1), 6),
            ]))
            
            story.append(face_table)
            story.append(Spacer(1, 0.1*inch))
        
        story.append(Spacer(1, 0.1*inch))
    else:
        # If no faces detected, still add a note
        story.append(Paragraph("3. FACE ANALYSIS DETAILS", styles['SectionHeader']))
        story.append(Paragraph("No faces detected in the image.", styles['NormalText']))
        story.append(Spacer(1, 0.2*inch))
    
    # 6. RECOMMENDATIONS (renumbered from 3 to 4)
    story.append(Paragraph("4. RECOMMENDATIONS", styles['SectionHeader']))
    
    if detection_results['explicit_detected'] or detection_results['deepfake_detected']:
        recommendations = [
            ["⚠️", "ACTIONS REQUIRED"],
            ["•", "Content requires immediate review"],
            ["•", "Do not share or publish this content"],
            ["•", "Report to appropriate authorities if needed"],
        ]
    else:
        recommendations = [
            ["✓", "SAFE CONTENT"],
            ["•", "Content appears safe to use"],
            ["•", "No immediate action required"],
        ]
    
    rec_table = Table(recommendations, colWidths=[0.3*inch, 6*inch])
    rec_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('SPAN', (0,0), (1,0)),  # Merge cells for header
        ('TEXTCOLOR', (0,0), (1,0), colors.HexColor('#c399ff') if 'SAFE' in recommendations[0][1] else colors.HexColor('#ff6b6b')),
        ('FONTNAME', (0,0), (1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (1,0), 12),
        ('LINEBELOW', (0,0), (1,0), 1, colors.HexColor('#dddddd')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(rec_table)
    story.append(Spacer(1, 0.2*inch))
    
    # 7. CRYPTOGRAPHIC TIMESTAMP (renumbered from 4 to 5)
    if crypto_timestamp:
        story.append(Paragraph("5. CRYPTOGRAPHIC TIMESTAMP", styles['SectionHeader']))
        
        timestamp_data = crypto_timestamp['data']
        
        # Create a beautiful boxed timestamp table
        timestamp_info = [
            ['Timestamp:', timestamp_data['timestamp']],
            ['Document Hash:', crypto_timestamp['hash']],
            ['Signature:', crypto_timestamp['signature']],
            ['Verification:', f'{APP_BASE_URL}/verify-timestamp'],
            ['Document Hash (for verification):', crypto_timestamp['hash']],
            ['Digital Signature (for verification):', crypto_timestamp['signature']],
        ]
        
        timestamp_table = Table(timestamp_info, colWidths=[1.5*inch, 5*inch])
        timestamp_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Courier'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#c399ff')),  # Purple border
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#1a1a1a')),  # Dark background
            ('TEXTCOLOR', (0,0), (-1,-1), colors.HexColor('#f0f0f0')),  # Light text
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('PADDING', (0,0), (-1,-1), 8),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#c399ff')),  # Purple labels
            ('FONTSIZE', (0,0), (0,-1), 9),
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#0a0a0a')),  # Even darker background
        ]))
        
        story.append(timestamp_table)
        story.append(Spacer(1, 0.1*inch))
        
        story.append(Paragraph(
            "This cryptographic timestamp proves when this analysis was performed "
            "and that the results have not been tampered with.",
            styles['ItalicText']
        ))
        story.append(Spacer(1, 0.2*inch))
    
    # 8. TECHNICAL DETAILS (renumbered from 5 to 6)
    story.append(Paragraph("6. TECHNICAL DETAILS", styles['SectionHeader']))
    
    tech_data = [
        ['Processing Time:', f"{processing_time:.1f} seconds"],
        ['Image Sharpness:', f"{image_metadata.get('sharpness', 0):.1f}%"],
        ['Brightness:', f"{image_metadata.get('brightness', 0):.1f}%"],
        ['File Hash:', file_hash[:32] + '...'],
    ]
    
    tech_table = Table(tech_data, colWidths=[1.5*inch, 5*inch])
    tech_table.setStyle(TableStyle([
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('TEXTCOLOR', (0,0), (0,-1), colors.HexColor('#c399ff')),  # Purple labels
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),  # Black values
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f9f9f9')),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(tech_table)
    story.append(Spacer(1, 0.2*inch))
    
    # 9. DISCLAIMER
    story.append(Paragraph("DISCLAIMER", styles['SectionHeader']))
    disclaimer_text = """
    This report is generated automatically by HerLens AI and is for informational purposes only. 
    Final determination should be made by human review. The cryptographic timestamp provided 
    can be verified at any time using the verification link above.
    """
    story.append(Paragraph(disclaimer_text, styles['ItalicText']))
    
    # Build PDF
    doc.build(story)
    
    # Encrypt PDF with custom password
    writer = PdfWriter()
    reader = PdfReader(temp_report_path)
    for page in reader.pages:
        writer.add_page(page)
    
    writer.encrypt(user_pwd=pdf_password)
    
    with open(report_path, "wb") as f:
        writer.write(f)
    
    os.remove(temp_report_path)
    return report_path, file_hash

# ============= OPENCV FACE DETECTION (NO TENSORFLOW REQUIRED) =============
DEEPFAKE_ENGINE_VERSION = 'opencv-yunet-v2'
_APP_ROOT = Path(__file__).resolve().parent
_YUNET_MODEL_PATH = str(_APP_ROOT / 'models' / 'face_detection_yunet_2023mar.onnx')
_LEGACY_YUNET_MODEL_PATH = str(_APP_ROOT / 'instance' / 'models' / 'face_detection_yunet_2023mar.onnx')
_YUNET_MODEL_URL = (
    'https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/'
    'face_detection_yunet_2023mar.onnx'
)
_OPENCV_FACE_CASCADE = None
_OPENCV_PROFILE_CASCADE = None
_YUNET_DETECTOR = None

def _ensure_yunet_model():
    if os.path.exists(_YUNET_MODEL_PATH):
        return _YUNET_MODEL_PATH
    if os.path.exists(_LEGACY_YUNET_MODEL_PATH):
        os.makedirs(os.path.dirname(_YUNET_MODEL_PATH), exist_ok=True)
        import shutil
        shutil.copy2(_LEGACY_YUNET_MODEL_PATH, _YUNET_MODEL_PATH)
        return _YUNET_MODEL_PATH
    os.makedirs(os.path.dirname(_YUNET_MODEL_PATH), exist_ok=True)
    try:
        import urllib.request
        logger.info('Downloading OpenCV YuNet face model (one-time)...')
        urllib.request.urlretrieve(_YUNET_MODEL_URL, _YUNET_MODEL_PATH)
        return _YUNET_MODEL_PATH
    except Exception as e:
        logger.error('YuNet model download failed: %s', e)
        return None

def detect_faces_yunet(img):
    """Detect faces with OpenCV YuNet DNN (accurate, no TensorFlow)."""
    global _YUNET_DETECTOR
    if not hasattr(cv2, 'FaceDetectorYN'):
        return []

    model_path = _ensure_yunet_model()
    if not model_path:
        return []

    height, width = img.shape[:2]
    if _YUNET_DETECTOR is None:
        _YUNET_DETECTOR = cv2.FaceDetectorYN.create(model_path, '', (320, 320), 0.6, 0.3, 5000)

    _YUNET_DETECTOR.setInputSize((width, height))
    _, faces = _YUNET_DETECTOR.detect(img)
    if faces is None:
        return []

    boxes = []
    for face in faces:
        x, y, w, h = face[:4]
        if w > 20 and h > 20:
            boxes.append((int(x), int(y), int(w), int(h)))
    return boxes

def _get_opencv_cascade(kind='frontal'):
    global _OPENCV_FACE_CASCADE, _OPENCV_PROFILE_CASCADE
    if kind == 'profile':
        if _OPENCV_PROFILE_CASCADE is None:
            path = os.path.join(cv2.data.haarcascades, 'haarcascade_profileface.xml')
            _OPENCV_PROFILE_CASCADE = cv2.CascadeClassifier(path)
        return _OPENCV_PROFILE_CASCADE
    if _OPENCV_FACE_CASCADE is None:
        path = os.path.join(cv2.data.haarcascades, 'haarcascade_frontalface_default.xml')
        _OPENCV_FACE_CASCADE = cv2.CascadeClassifier(path)
    return _OPENCV_FACE_CASCADE

def detect_faces_opencv(gray, img_bgr=None):
    """Detect faces using YuNet DNN, then OpenCV Haar cascades."""
    if img_bgr is not None:
        yunet_faces = detect_faces_yunet(img_bgr)
        if yunet_faces:
            return yunet_faces

    detected = []
    variants = [gray]
    try:
        variants.append(cv2.equalizeHist(gray))
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        variants.append(clahe.apply(gray))
    except Exception:
        pass

    for variant in variants:
        for kind in ('frontal', 'profile'):
            cascade = _get_opencv_cascade(kind)
            if cascade.empty():
                continue
            for scale_factor, min_neighbors in ((1.05, 3), (1.1, 4), (1.15, 5)):
                faces = cascade.detectMultiScale(
                    variant,
                    scaleFactor=scale_factor,
                    minNeighbors=min_neighbors,
                    minSize=(40, 40),
                )
                for (x, y, w, h) in faces:
                    detected.append((int(x), int(y), int(w), int(h)))

    if not detected:
        return []

    # Merge overlapping boxes and keep the largest distinct faces
    detected.sort(key=lambda box: box[2] * box[3], reverse=True)
    merged = []
    for box in detected:
        x, y, w, h = box
        cx, cy = x + w / 2, y + h / 2
        overlaps = False
        for mx, my, mw, mh in merged:
            mcx, mcy = mx + mw / 2, my + mh / 2
            dist = ((cx - mcx) ** 2 + (cy - mcy) ** 2) ** 0.5
            if dist < min(w, h) * 0.35:
                overlaps = True
                break
        if not overlaps:
            merged.append(box)
    return merged

def analyze_face_synthetic_artifacts(img, x, y, w, h):
    """
    Heuristic analysis of a face crop for GAN / deepfake-style artifacts.
    Returns a suspicion score from 0-60 (higher = more likely synthetic).
    """
    height, width = img.shape[:2]
    x1, y1 = max(0, x), max(0, y)
    x2, y2 = min(width, x + w), min(height, y + h)
    face = img[y1:y2, x1:x2]
    if face.size == 0 or face.shape[0] < 40 or face.shape[1] < 40:
        return 0

    gray_face = cv2.cvtColor(face, cv2.COLOR_BGR2GRAY)
    fh, fw = gray_face.shape
    suspicion = 0

    # Left-right asymmetry (common in generated portraits)
    mid = fw // 2
    left = gray_face[:, :mid].astype(np.float32)
    right = cv2.flip(gray_face[:, fw - mid:], 1).astype(np.float32)
    min_w = min(left.shape[1], right.shape[1])
    if min_w > 0:
        asymmetry = np.mean(np.abs(left[:, :min_w] - right[:, :min_w]))
        if asymmetry > 10:
            suspicion += 12
        if asymmetry > 18:
            suspicion += 8

    # Abnormal bright specks in eye region (GAN highlight artifact)
    eye_band = gray_face[int(fh * 0.18):int(fh * 0.48), :]
    if eye_band.size > 0:
        bright_ratio = float(np.mean(eye_band > 195))
        very_bright_ratio = float(np.mean(eye_band > 220))
        if bright_ratio > 0.015:
            suspicion += 18
        if very_bright_ratio > 0.006:
            suspicion += 10

    # Uneven channel texture (color bleeding in synthetic skin)
    b, g, r = cv2.split(face)
    channel_stds = [float(np.std(b)), float(np.std(g)), float(np.std(r))]
    if max(channel_stds) - min(channel_stds) > 12:
        suspicion += 12

    # Local texture: overly smooth patches mixed with noisy patches
    lap = cv2.Laplacian(gray_face, cv2.CV_64F)
    lap_var = float(lap.var())
    if 80 < lap_var < 320:
        block_vars = []
        step_y, step_x = max(fh // 3, 1), max(fw // 3, 1)
        for by in range(0, fh - step_y, step_y):
            for bx in range(0, fw - step_x, step_x):
                patch = lap[by:by + step_y, bx:bx + step_x]
                block_vars.append(float(patch.var()))
        if block_vars and max(block_vars) > min(block_vars) * 2.5:
            suspicion += 14

    # High-frequency FFT energy outside the low-frequency center
    float_face = gray_face.astype(np.float32)
    spectrum = np.fft.fftshift(np.fft.fft2(float_face))
    magnitude = np.log1p(np.abs(spectrum))
    ch, cw = magnitude.shape
    cy, cx = ch // 2, cw // 2
    radius = max(min(ch, cw) // 8, 4)
    y_grid, x_grid = np.ogrid[:ch, :cw]
    center_mask = (y_grid - cy) ** 2 + (x_grid - cx) ** 2 <= radius ** 2
    center_energy = float(np.mean(magnitude[center_mask]))
    outer_energy = float(np.mean(magnitude[~center_mask]))
    if center_energy > 0 and outer_energy / center_energy > 0.55:
        suspicion += 12

    # Mouth/lip discoloration band
    mouth_band = face[int(fh * 0.62):int(fh * 0.88), int(fw * 0.2):int(fw * 0.8)]
    if mouth_band.size > 0:
        mouth_hsv = cv2.cvtColor(mouth_band, cv2.COLOR_BGR2HSV)
        saturation = mouth_hsv[:, :, 1]
        if float(np.std(saturation)) > 45:
            suspicion += 8

    return min(suspicion, 60)

def analyze_portrait_frame(img):
    """
    When detectors fail on a tight face portrait, analyze the main subject region.
    """
    height, width = img.shape[:2]
    if height < 180 or width < 180:
        return 0, None

    aspect = width / max(height, 1)
    if not (0.55 <= aspect <= 1.6):
        return 0, None

    margin_x = int(width * 0.07)
    margin_y = int(height * 0.04)
    box = (margin_x, margin_y, width - 2 * margin_x, height - 2 * margin_y)
    score = analyze_face_synthetic_artifacts(img, *box)
    return score, box

def _append_opencv_face_results(img, face_boxes, face_analyses, score):
    """Score detected face boxes and return updated score."""
    face_count = len(face_boxes)
    for (x, y, w, h) in face_boxes:
        synthetic_score = analyze_face_synthetic_artifacts(img, x, y, w, h)
        is_real = synthetic_score < 22
        if synthetic_score >= 22:
            score += min(synthetic_score, 45)
            print(f"      ⚠️ Face artifact score: {synthetic_score}")
        face_analyses.append({
            'age': 'unknown',
            'gender': 'unknown',
            'gender_confidence': 0,
            'dominant_emotion': 'unknown',
            'is_real': is_real,
            'antispoof_score': synthetic_score,
            'face_area': w * h,
            'synthetic_score': synthetic_score,
        })

    if face_count >= 2:
        score += 35
        print("   ⚠️ Multiple faces detected - suspicious composite image")
    elif face_count == 1:
        score += 15
    return score, face_count

def should_flag_deepfake(score, face_count=0):
    """Consistent threshold for marking an image as suspicious."""
    if face_count >= 2:
        return score >= 35
    return score >= 40

def detect_faces_mtcnn(img):
    """Optional TensorFlow-based fallback when OpenCV finds nothing."""
    try:
        from mtcnn import MTCNN
        detector = MTCNN()
        rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        faces = detector.detect_faces(rgb)
        boxes = []
        for face in faces:
            x, y, w, h = face['box']
            boxes.append((max(0, x), max(0, y), max(0, w), max(0, h)))
        return boxes
    except Exception as e:
        print(f"   MTCNN fallback unavailable: {e}")
        return []

# ============= DEEPFAKE DETECTION WITH FALLBACK HEURISTICS =============
def detect_deepfake(filepath):
    """
    Detect deepfake-style images using DeepFace when available and a robust heuristics fallback
    when it is not. This makes composite or mixed-face images more likely to be flagged.
    """
    try:
        import numpy as np

        img = cv2.imread(filepath)
        if img is None:
            return 10, []

        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        brightness = np.mean(gray)
        contrast = np.std(gray)

        face_analyses = []
        score = 20
        face_count = 0

        if DEEPFACE_AVAILABLE:
            try:
                face_objs = DeepFace.extract_faces(
                    img_path=filepath,
                    detector_backend='retinaface',
                    enforce_detection=False,
                    anti_spoofing=True
                )

                if face_objs and len(face_objs) > 0:
                    face_count = len(face_objs)
                    print(f"   Detected {face_count} face(s) with DeepFace")

                    for face_obj in face_objs:
                        is_real = face_obj.get('is_real', True)
                        antispoof_score = face_obj.get('antispoof_score', 0)
                        if not is_real:
                            score += 40
                            print("      ⚠️ Anti-spoofing flagged as fake")

                        face_analyses.append({
                            'age': 'unknown',
                            'gender': 'unknown',
                            'gender_confidence': 0,
                            'dominant_emotion': 'unknown',
                            'is_real': is_real,
                            'antispoof_score': antispoof_score
                        })

                    if face_count >= 2:
                        score += 45
                        print("   ⚠️ Multiple faces detected - suspicious composite image")
                    else:
                        score += 25
                else:
                    print("   No faces detected by DeepFace")
            except Exception as e:
                print(f"   DeepFace analysis failed: {e}")

        # OpenCV face detection when DeepFace did not populate results
        if not face_analyses:
            opencv_faces = detect_faces_opencv(gray, img)
            if opencv_faces:
                face_count = len(opencv_faces)
                print(f"   Detected {face_count} face(s) with OpenCV")
                score, face_count = _append_opencv_face_results(
                    img, opencv_faces, face_analyses, score
                )
            else:
                print("   No faces detected by OpenCV")

        # Portrait-style image: analyze the main subject region if still no face box
        if not face_analyses:
            portrait_score, portrait_box = analyze_portrait_frame(img)
            if portrait_score >= 18 and portrait_box:
                x, y, w, h = portrait_box
                face_count = 1
                print(f"   Portrait-region artifact score: {portrait_score}")
                score += min(portrait_score + 18, 55)
                face_analyses.append({
                    'age': 'unknown',
                    'gender': 'unknown',
                    'gender_confidence': 0,
                    'dominant_emotion': 'unknown',
                    'is_real': portrait_score < 22,
                    'antispoof_score': portrait_score,
                    'face_area': w * h,
                    'synthetic_score': portrait_score,
                })

        # Last resort: MTCNN only if OpenCV also found nothing
        if not face_analyses:
            mtcnn_faces = detect_faces_mtcnn(img)
            if mtcnn_faces:
                face_count = len(mtcnn_faces)
                print(f"   Detected {face_count} face(s) with MTCNN")
                for (x, y, w, h) in mtcnn_faces:
                    synthetic_score = analyze_face_synthetic_artifacts(img, x, y, w, h)
                    face_analyses.append({
                        'age': 'unknown',
                        'gender': 'unknown',
                        'gender_confidence': 0,
                        'dominant_emotion': 'unknown',
                        'is_real': synthetic_score < 22,
                        'antispoof_score': synthetic_score,
                        'face_area': w * h,
                        'synthetic_score': synthetic_score,
                    })
                    if synthetic_score >= 22:
                        score += min(synthetic_score, 40)
                if face_count >= 2:
                    score += 35
                else:
                    score += 15
            else:
                score += 15
                print("   ⚠️ No faces detected by any detector")

        # Heuristic checks for suspicious image quality/common composite artifacts
        if laplacian_var < 100:
            score += 25
            print(f"   ⚠️ Low sharpness detected: {laplacian_var:.1f}")
        if contrast < 35:
            score += 25
            print("   ⚠️ Low contrast detected")
        if brightness < 55 or brightness > 200:
            score += 15
            print("   ⚠️ Unnatural brightness detected")

        # Detect strong center seam that may indicate a manually merged face
        edges = cv2.Canny(gray, 50, 150)
        center_slice = edges[:, max(0, edges.shape[1] // 2 - 10):min(edges.shape[1], edges.shape[1] // 2 + 10)]
        center_edge_strength = np.sum(center_slice) / 255.0
        overall_edge_strength = np.sum(edges) / 255.0
        if overall_edge_strength > 0 and center_edge_strength > overall_edge_strength * 0.15:
            score += 30
            print("   ⚠️ Strong vertical seam detected - possible composite merge")

        if len(face_analyses) >= 2:
            areas = [item.get('face_area', 0) for item in face_analyses if 'face_area' in item]
            if areas and max(areas) / max(min(areas), 1) > 3:
                score += 20
                print("   ⚠️ Faces differ strongly in size - possible composite")

        # Force a suspicious rating when face detection fails but low-quality / composite artifacts are present
        if face_count == 0 and (laplacian_var < 100 or contrast < 35 or brightness < 55 or brightness > 200):
            score = max(score, 55)
            print("   ⚠️ Heuristic fallback triggered - rating as suspicious")

        # Portrait-shaped image with no detected face is mildly suspicious
        img_h, img_w = gray.shape[:2]
        if face_count == 0 and img_h > 200 and img_w > 200:
            aspect = img_w / max(img_h, 1)
            if 0.5 <= aspect <= 1.4:
                score = max(score, 48)
                print("   ⚠️ Portrait-shaped image with no detected face")

        score = min(max(score, 20), 100)
        print(f"\n📊 FINAL DEEPFAKE SCORE: {score}%")
        return score, face_analyses

    except Exception as e:
        print(f"Deepfake detection error: {e}")
        return 30, []

# ============= FIXED NUDENET DETECTION =============
def detect_explicit_content(filepath):
    """
    Detect explicit content using NudeNet with proper confidence scoring
    """
    try:
        results = detector.detect(filepath)
        
        explicit_detected = False
        explicit_confidence = 0
        explicit_classes = []
        
        print("\n" + "="*60)
        print("🔍 NudeNet Detection Results:")
        print("="*60)
        
        for r in results:
            label = r.get('label', '').upper()
            # NudeNet confidence is between 0-1, convert to percentage
            confidence = r.get('confidence', 0) * 100
            box = r.get('box', [0,0,0,0])
            
            print(f"\n📌 Label: {label}")
            print(f"   Confidence: {confidence:.2f}%")
            print(f"   Box: {box}")
            
            # Check against unsafe categories
            matched = False
            for unsafe_cat in UNSAFE_CATEGORIES:
                if unsafe_cat in label:
                    print(f"   ⚠️ UNSAFE - Matched: {unsafe_cat}")
                    explicit_detected = True
                    explicit_confidence = max(explicit_confidence, confidence)
                    explicit_classes.append({
                        'label': label,
                        'confidence': confidence,
                        'box': box
                    })
                    matched = True
                    break
            
            if not matched:
                print(f"   ✅ SAFE - Not in unsafe categories")
        
        # Even if no matches, set a baseline confidence if there are detections
        if not explicit_detected and results:
            # If objects detected but none unsafe, confidence is low
            explicit_confidence = max([r.get('confidence', 0) * 100 for r in results]) * 0.3
            print(f"\n   ℹ️ Objects detected but all safe - baseline confidence: {explicit_confidence:.1f}%")
        
        print("\n" + "="*60)
        print(f"📊 FINAL DECISION:")
        print(f"   Explicit Detected: {explicit_detected}")
        print(f"   Max Confidence: {explicit_confidence:.2f}%")
        print(f"   Matched Classes: {len(explicit_classes)}")
        print("="*60 + "\n")
        
        return explicit_detected, explicit_confidence, explicit_classes
        
    except Exception as e:
        print(f"NudeNet detection error: {e}")
        return False, 0, []

# ============= IMAGE QUALITY ANALYSIS =============
def analyze_image_quality(filepath):
    """
    Analyze image quality metrics
    """
    try:
        img = cv2.imread(filepath)
        if img is None:
            return {'sharpness': 0, 'brightness': 50, 'width': 0, 'height': 0, 'format': 'Unknown'}
        
        height, width = img.shape[:2]
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        variance_of_laplacian = cv2.Laplacian(gray, cv2.CV_64F).var()
        sharpness = min(variance_of_laplacian / 500 * 100, 100)
        brightness = np.mean(gray) / 255.0 * 100
        format_type = os.path.splitext(filepath)[1].upper().replace('.', '')
        
        return {
            'sharpness': round(sharpness, 1),
            'brightness': round(brightness, 1),
            'width': width,
            'height': height,
            'format': format_type,
        }
        
    except Exception as e:
        print("Image quality analysis error:", e)
        return {'sharpness': 50, 'brightness': 50, 'width': 0, 'height': 0, 'format': 'Unknown'}

# ============= ROUTES =============
@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/history')
@admin_required
def view_history():
    """View all analyses"""
    analyses = Analysis.query.order_by(Analysis.created_at.desc()).limit(50).all()
    return render_template('history.html', analyses=analyses)

@app.route('/user/<email>')
@admin_required
def user_history(email):
    """View analyses for specific user"""
    user = User.query.filter_by(email=email).first()
    if not user:
        return f"User {email} not found. <a href='/'>Upload an image first!</a>"
    analyses = Analysis.query.filter_by(user_id=user.id).order_by(Analysis.created_at.desc()).all()
    return render_template('user_history.html', user=user, analyses=analyses)

@app.route('/stats')
@admin_required
def stats():
    """View statistics"""
    total_users = User.query.count()
    total_analyses = Analysis.query.count()
    high_risk = Analysis.query.filter(Analysis.risk_level.in_(['HIGH RISK', 'CRITICAL RISK'])).count()
    safe = Analysis.query.filter_by(risk_level='SAFE').count()
    
    recent = Analysis.query.order_by(Analysis.created_at.desc()).limit(10).all()
    
    return render_template('stats.html',
                          total_users=total_users,
                          total_analyses=total_analyses,
                          high_risk=high_risk,
                          safe=safe,
                          recent=recent)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"

    file = request.files['file']
    email = request.form.get('email')
    
    if file.filename == '':
        return "No file selected"
    
    if not email or not is_valid_email(email):
        return "A valid email address is required", 400

    logger.info("Processing upload request")

    # Start timing
    start_time = time.time()

    try:
        stored_filename = create_stored_upload_filename(file.filename)
    except ValueError:
        return "Unsupported file type. Please upload a JPG, PNG, GIF, or WEBP image.", 400

    display_filename = secure_filename(file.filename.replace(' ', '_')) or stored_filename
    static_filepath = os.path.join(STATIC_UPLOAD_FOLDER, stored_filename)
    file.save(static_filepath)

    # Analyze image quality
    image_metadata = analyze_image_quality(static_filepath)

    # ===== DETECT EXPLICIT CONTENT WITH CONFIDENCE =====
    explicit_detected, explicit_confidence, explicit_classes = detect_explicit_content(static_filepath)

    # ===== DETECT DEEPFAKES WITH CONFIDENCE =====
    deepfake_confidence, face_analyses = detect_deepfake(static_filepath)
    deepfake_detected = should_flag_deepfake(
        deepfake_confidence,
        face_count=len(face_analyses),
    )
    logger.info(
        'Deepfake analysis [%s]: score=%s%% faces=%s detected=%s',
        DEEPFAKE_ENGINE_VERSION,
        deepfake_confidence,
        len(face_analyses),
        deepfake_detected,
    )

    # Calculate processing time
    processing_time = time.time() - start_time

    # Generate random password for this report
    pdf_password = generate_random_password()

    # ===== IMPROVED RISK ASSESSMENT WITH CONFIDENCE THRESHOLDS =====
    if explicit_confidence > 70:
        if deepfake_detected:
            risk_level = "CRITICAL RISK"
            action = "⚠️ URGENT: High confidence explicit content AND AI-generated content detected!"
        else:
            risk_level = "HIGH RISK"
            action = "⚠️ IMMEDIATE ACTION: Explicit content detected with high confidence!"
    elif explicit_confidence > 40:
        if deepfake_detected:
            risk_level = "HIGH RISK"
            action = "⚠️ Review needed: Moderate confidence explicit + AI content detected"
        else:
            risk_level = "MODERATE RISK"
            action = "⚠️ Review suggested: Potential explicit content detected"
    elif explicit_confidence > 15:
        risk_level = "LOW RISK"
        action = "⚠️ Low confidence detection - review if concerned"
    else:
        if deepfake_detected and deepfake_confidence >= 70:
            risk_level = "HIGH RISK"
            action = "⚠️ AI-generated content detected with high confidence!"
        elif deepfake_detected:
            risk_level = "MODERATE RISK"
            action = "⚠️ Possible AI-generated content detected"
        else:
            risk_level = "SAFE"
            action = "✓ No issues detected - content appears safe"

    # Prepare detection results for report
    detection_results = {
        'explicit_detected': explicit_detected,
        'deepfake_detected': deepfake_detected,
        'explicit_confidence': explicit_confidence,
        'deepfake_confidence': deepfake_confidence,
        'explicit_classes': explicit_classes,
        'processing_time': processing_time,
        'risk_level': risk_level
    }

    # ===== CREATE CRYPTOGRAPHIC TIMESTAMP =====
    # We need analysis_id, but it's not created yet. We'll create timestamp after saving to DB
    # For now, prepare data
    timestamp_data = {
        'filename': display_filename,
        'explicit_confidence': explicit_confidence,
        'deepfake_confidence': deepfake_confidence,
        'risk_level': risk_level,
        'user_email': email
    }

    # Generate encrypted PDF report (without timestamp first)
    report_path, file_hash = generate_report(
        static_filepath, 
        display_filename, 
        detection_results, 
        face_analyses, 
        image_metadata,
        processing_time,
        pdf_password,
        crypto_timestamp=None  # Will add after DB save
    )

    # Send password to user's email
    logger.info("Attempting to send password email")
    email_sent = send_password_email(email, pdf_password, display_filename, risk_level)

    # ============= SAVE TO DATABASE =============
    try:
        # Find or create user
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email)
            db.session.add(user)
            db.session.flush()
        
        # Create analysis record (without timestamp first)
        analysis = Analysis(
            user_id=user.id,
            filename=display_filename,
            file_hash=file_hash[:64],
            file_size=os.path.getsize(static_filepath) / (1024*1024),
            image_dimensions=f"{image_metadata.get('width', 0)}x{image_metadata.get('height', 0)}",
            explicit_detected=explicit_detected,
            explicit_confidence=explicit_confidence,
            deepfake_detected=deepfake_detected,
            deepfake_confidence=deepfake_confidence,
            risk_level=risk_level,
            action_taken=action,
            pdf_password=None,
            pdf_path=os.path.basename(report_path),
            email_sent=email_sent,
            processing_time=processing_time
        )
        
        db.session.add(analysis)
        db.session.flush()  # Get analysis.id
        
        # ===== NOW CREATE TIMESTAMP WITH ANALYSIS ID =====
        timestamp_data['analysis_id'] = analysis.id
        crypto_timestamp, json_string = create_crypto_timestamp(timestamp_data)
        
        # Update analysis with timestamp data
        analysis.crypto_timestamp = json.dumps(crypto_timestamp)
        analysis.timestamp_hash = crypto_timestamp['hash']
        analysis.timestamp_signature = crypto_timestamp['signature']
        
        user.total_analyses += 1
        db.session.commit()
        logger.info("Saved to database: Analysis #%s", analysis.id)
        
        # ===== REGENERATE PDF WITH TIMESTAMP =====
        # Add timestamp and analysis_id to detection results
        detection_results['crypto_timestamp'] = crypto_timestamp
        detection_results['analysis_id'] = analysis.id  # ADDED: Analysis ID for report
        
        # Regenerate report with timestamp
        new_report_path, _ = generate_report(
            static_filepath, 
            display_filename, 
            detection_results, 
            face_analyses, 
            image_metadata,
            processing_time,
            pdf_password,
            crypto_timestamp=crypto_timestamp
        )
        
        # Update pdf_path in database
        analysis.pdf_path = os.path.basename(new_report_path)
        db.session.commit()
        
        report_path = new_report_path  # Use new report path
        
    except Exception as e:
        db.session.rollback()
        logger.error("Database error while saving analysis")

    # Get image URL for preview
    image_url = url_for('static', filename=f'uploads/{stored_filename}')

    return render_template('result.html',
                           filename=display_filename,
                           risk_level=risk_level,
                           confidence=deepfake_confidence,
                           deepfake_confidence=deepfake_confidence,
                           explicit_confidence=explicit_confidence,
                           action=action,
                           image_url=image_url,
                           explicit_detected=explicit_detected,
                           deepfake_detected=deepfake_detected,
                           report_filename=os.path.basename(report_path),
                           email=email,
                           email_sent=email_sent,
                           analysis_id=analysis.id if 'analysis' in locals() else None,
                           report_download_url=build_download_url(
                               analysis.id, os.path.basename(report_path)
                           ) if 'analysis' in locals() else None)

@app.route('/download_report/<filename>')
def download_report(filename):
    safe_name = secure_filename(filename)
    report_path = safe_report_path(safe_name)
    analysis = Analysis.query.filter_by(pdf_path=safe_name).first()
    token = request.args.get('token', '')

    time.sleep(0.2)

    if (
        not report_path
        or not analysis
        or not verify_download_token(analysis.id, analysis.pdf_path, token)
        or not os.path.exists(report_path)
    ):
        return "Report not found.", 404

    return send_file(report_path, as_attachment=True)

# ===== NEW ROUTE: Verify Cryptographic Timestamp =====
@app.route('/verify-timestamp', methods=['GET', 'POST'])
def verify_timestamp():
    """Verify a cryptographic timestamp using hash and signature from the PDF report."""
    document_hash = normalize_crypto_input(
        request.form.get('document_hash') or request.args.get('hash') or request.args.get('document_hash')
    )
    digital_signature = normalize_crypto_input(
        request.form.get('digital_signature') or request.args.get('signature') or request.args.get('digital_signature')
    )

    if not document_hash or not digital_signature:
        return render_template(
            'verify_form.html',
            error=request.args.get('analysis_id') and (
                'Analysis ID alone cannot verify a report. '
                'Enter the Document Hash and Digital Signature from your PDF.'
            ) or None,
            prefilled_hash=document_hash,
            prefilled_signature=digital_signature,
        )

    analysis = Analysis.query.filter_by(
        timestamp_hash=document_hash,
        timestamp_signature=digital_signature,
    ).first()

    if not analysis:
        return render_template(
            'verify.html',
            analysis=None,
            record_found=False,
            is_valid=False,
            hash_valid=False,
            signature_valid=False,
            submitted_hash_valid=False,
            submitted_signature_valid=False,
            db_integrity_valid=False,
            stored_timestamp=None,
            verification_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            error_message=(
                'No matching analysis was found for the provided hash and signature. '
                'The report may be forged, altered, or not issued by this system.'
            ),
        )

    stored_crypto = json.loads(analysis.crypto_timestamp) if analysis.crypto_timestamp else None
    if not stored_crypto:
        return render_template(
            'verify.html',
            analysis=analysis,
            record_found=True,
            is_valid=False,
            hash_valid=False,
            signature_valid=False,
            submitted_hash_valid=False,
            submitted_signature_valid=False,
            db_integrity_valid=False,
            stored_timestamp=None,
            verification_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            error_message='This analysis record has no cryptographic timestamp data.',
        )

    hash_valid, signature_valid, calculated_hash, calculated_signature = verify_crypto_package(stored_crypto)
    submitted_hash_valid = constant_time_compare(document_hash, stored_crypto.get('hash', ''))
    submitted_signature_valid = constant_time_compare(digital_signature, stored_crypto.get('signature', ''))
    db_integrity_valid = signed_data_matches_analysis(analysis, stored_crypto.get('data', {}))

    is_valid = (
        hash_valid
        and signature_valid
        and submitted_hash_valid
        and submitted_signature_valid
        and db_integrity_valid
    )

    return render_template(
        'verify.html',
        analysis=analysis,
        record_found=True,
        is_valid=is_valid,
        hash_valid=hash_valid,
        signature_valid=signature_valid,
        submitted_hash_valid=submitted_hash_valid,
        submitted_signature_valid=submitted_signature_valid,
        db_integrity_valid=db_integrity_valid,
        stored_timestamp=stored_crypto,
        calculated_hash=calculated_hash,
        calculated_signature=calculated_signature,
        verification_time=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        error_message=None if is_valid else (
            'Verification failed. The hash/signature pair does not match a valid signed payload, '
            'or the stored analysis data no longer matches what was originally signed.'
        ),
    )

# Test route to verify email
@app.route('/test-email', methods=['GET', 'POST'])
@debug_only
def test_email():
    if request.method == 'POST':
        test_email = request.form.get('email')
        result = send_password_email(
            recipient_email=test_email,
            password='TestPass123!@#',
            filename='test_image.jpg',
            risk_level='SAFE'
        )
        if result:
            return f"""
            <div style="text-align: center; padding: 50px; background: #0a0a0a; color: #c399ff;">
                <h1>✅ SUCCESS!</h1>
                <p>Test email sent to {test_email}</p>
                <p>Check your inbox (and SPAM folder)</p>
                <a href="/" style="color: #c399ff;">Return to HerLens</a>
            </div>
            """
        else:
            return f"""
            <div style="text-align: center; padding: 50px; background: #0a0a0a; color: #ff6b6b;">
                <h1>❌ FAILED</h1>
                <p>Could not send to {test_email}</p>
                <p>Check console for error details</p>
                <a href="/test-email" style="color: #c399ff;">Try Again</a>
            </div>
            """
    
    return '''
    <div style="text-align: center; padding: 50px; background: #0a0a0a; color: #c399ff;">
        <h1>📧 Test Email Configuration</h1>
        <form method="post">
            <input type="email" name="email" placeholder="Enter your email" required
                   style="padding: 10px; width: 300px; margin: 20px; border-radius: 5px;">
            <br>
            <button type="submit" style="padding: 10px 30px; background: #c399ff; border: none; border-radius: 5px; cursor: pointer;">
                Send Test Email
            </button>
        </form>
    </div>
    '''

# ============= DEBUG ROUTES FOR TESTING DETECTION =============
@app.route('/debug-nudenet')
@debug_only
def debug_nudenet():
    return '''
    <div style="text-align: center; padding: 50px; background: #0a0a0a; color: #c399ff;">
        <h1>🔍 Debug NudeNet</h1>
        <form action="/debug-nudenet-upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept="image/*" required
                   style="padding: 10px; margin: 20px;">
            <br>
            <button type="submit" style="padding: 10px 30px; background: #c399ff; border: none; border-radius: 5px;">
                Test Detection
            </button>
        </form>
    </div>
    '''

@app.route('/debug-nudenet-upload', methods=['POST'])
@debug_only
def debug_nudenet_upload():
    if 'file' not in request.files:
        return "No file"

    file = request.files['file']
    try:
        filename = create_stored_upload_filename(file.filename)
    except ValueError:
        return "Unsupported file type", 400

    filepath = os.path.join(STATIC_UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    # Run detection
    results = detector.detect(filepath)
    
    html = f"<h2>Results for {file.filename}:</h2><pre>"
    for r in results:
        label = r.get('label', 'unknown')
        score = r.get('score', r.get('confidence', 0)) * 100
        box = r.get('box', [0,0,0,0])
        
        # Check if unsafe
        is_unsafe = False
        for cat in UNSAFE_CATEGORIES:
            if cat in label.upper():
                is_unsafe = True
                break
        
        status = "⚠️ UNSAFE" if is_unsafe else "✅ SAFE"
        html += f"{status} - {label}: {score:.1f}%\n"
    
    html += "</pre><br><a href='/debug-nudenet'>Back</a>"
    return html

@app.route('/debug-deepfake')
@debug_only
def debug_deepfake():
    return '''
    <div style="text-align: center; padding: 50px; background: #0a0a0a; color: #c399ff;">
        <h1>🔍 Debug Deepfake Detection</h1>
        <form action="/debug-deepfake-upload" method="post" enctype="multipart/form-data">
            <input type="file" name="file" accept="image/*" required
                   style="padding: 10px; margin: 20px;">
            <br>
            <button type="submit" style="padding: 10px 30px; background: #c399ff; border: none; border-radius: 5px;">
                Test Deepfake Detection
            </button>
        </form>
    </div>
    '''

@app.route('/debug-deepfake-upload', methods=['POST'])
@debug_only
def debug_deepfake_upload():
    if 'file' not in request.files:
        return "No file"

    file = request.files['file']
    try:
        filename = create_stored_upload_filename(file.filename)
    except ValueError:
        return "Unsupported file type", 400

    filepath = os.path.join(STATIC_UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    # Run deepfake detection
    deepfake_score, face_analyses = detect_deepfake(filepath)
    
    html = f"<h2>Deepfake Analysis for {file.filename}:</h2>"
    html += f"<p><strong>Overall Deepfake Score:</strong> {deepfake_score}%</p>"
    html += f"<p><strong>Faces Detected:</strong> {len(face_analyses)}</p>"
    
    if face_analyses:
        html += "<h3>Face Details:</h3><pre>"
        for i, face in enumerate(face_analyses):
            html += f"\nFace #{i+1}:\n"
            html += f"  Age: {face['age']}\n"
            html += f"  Gender: {face['gender']} ({face['gender_confidence']:.1f}%)\n"
            html += f"  Emotion: {face['dominant_emotion']}\n"
            html += f"  Is Real: {face.get('is_real', 'N/A')}\n"
            html += f"  Anti-spoof Score: {face.get('antispoof_score', 'N/A')}\n"
        html += "</pre>"
    
    html += "<br><a href='/debug-deepfake'>Back</a>"
    return html

if __name__ == '__main__':
    import socket
    import sys

    def _port_available(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('127.0.0.1', port))
                return True
            except OSError:
                return False

    with app.app_context():
        db.create_all()
    logger.info('HerLens deepfake engine: %s', DEEPFAKE_ENGINE_VERSION)
    logger.info('App file: %s', Path(__file__).resolve())
    logger.info('YuNet model ready: %s', bool(_ensure_yunet_model()))

    run_port = int(os.getenv('FLASK_PORT', '5000'))
    if not _port_available(run_port):
        fallback_port = run_port + 1
        if _port_available(fallback_port):
            logger.warning(
                'Port %s is already in use by old server(s). Starting on http://127.0.0.1:%s instead.',
                run_port,
                fallback_port,
            )
            run_port = fallback_port
        else:
            logger.error(
                'Ports %s and %s are in use. End extra python.exe processes in Task Manager, then restart.',
                run_port,
                fallback_port,
            )
            sys.exit(1)

    logger.info('Open the app at http://127.0.0.1:%s', run_port)
    debug_mode = env_bool('FLASK_DEBUG', True)
    app.run(debug=debug_mode, port=run_port)