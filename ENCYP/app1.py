from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'aes_web_app_secret_key_2024_very_strong_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# IMPORTANT: Session configuration
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.config['SESSION_COOKIE_SECURE'] = False  # For development
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Create folders if not exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

# AES Functions (same as before)
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path: str, password: str, output_path: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    with open(output_path, 'wb') as file:
        file.write(salt + iv + ciphertext)
    
    return True

def decrypt_file(encrypted_path: str, password: str, output_path: str):
    with open(encrypted_path, 'rb') as file:
        data = file.read()
    
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    with open(output_path, 'wb') as file:
        file.write(decrypted_data)
    
    return True

# Routes - FIXED VERSION
@app.route('/')
def index():
    print(f"🔍 Session in index: {session}")
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    print(f"🔐 Login attempt: {username}")
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password_hash(user[2], password):
        session['username'] = username
        session.permanent = True  # Important fix!
        print(f"✅ Login SUCCESS: {username}, Session: {session}")
        return redirect(url_for('dashboard'))
    else:
        print(f"❌ Login FAILED: {username}")
        return "Invalid credentials! <a href='/'>Try again</a>"

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    
    print(f"📝 Register attempt: {username}")
    
    hashed_password = generate_password_hash(password)
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                 (username, hashed_password))
        conn.commit()
        conn.close()
        print(f"✅ Registration SUCCESS: {username}")
        return f"Registration successful! Welcome {username} 🎉<br><a href='/'>Login now</a>"
    except Exception as e:
        print(f"❌ Registration FAILED: {username}, Error: {e}")
        return "Username already exists! <a href='/'>Try again</a>"

@app.route('/dashboard')
def dashboard():
    print(f"🔍 Dashboard check - Session: {session}")
    if 'username' in session:
        username = session['username']
        print(f"✅ Dashboard ACCESS: {username}")
        return render_template('dashboard.html', username=username)
    else:
        print("❌ Dashboard BLOCKED: No session")
        return redirect(url_for('index'))

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    # ... rest of encrypt function same as before
    if 'file' not in request.files:
        return "No file selected!"
    
    file = request.files['file']
    password = request.form['password']
    
    if file.filename == '':
        return "No file selected!"
    
    original_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(original_path)
    
    encrypted_path = original_path + '.encrypted'
    
    try:
        encrypt_file(original_path, password, encrypted_path)
        os.remove(original_path)
        return send_file(encrypted_path, as_attachment=True, download_name=file.filename + '.encrypted')
    except Exception as e:
        return f"Encryption failed: {str(e)}"

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    # ... rest of decrypt function same as before
    if 'file' not in request.files:
        return "No file selected!"
    
    file = request.files['file']
    password = request.form['password']
    
    if file.filename == '':
        return "No file selected!"
    
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(encrypted_path)
    
    decrypted_path = encrypted_path.replace('.encrypted', '_decrypted')
    
    try:
        decrypt_file(encrypted_path, password, decrypted_path)
        os.remove(encrypted_path)
        original_name = file.filename.replace('.encrypted', '')
        return send_file(decrypted_path, as_attachment=True, download_name=original_name)
    except Exception as e:
        return f"Decryption failed: {str(e)}"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/debug')
def debug():
    return f"""
    <h1>Debug Info</h1>
    <p>Session: {session}</p>
    <p>Username in session: {'username' in session}</p>
    <p><a href="/">Home</a></p>
    """

if __name__ == '__main__':
    init_db()
    print("🚀 Starting Flask Server with FIXED Sessions...")
    app.run(debug=True, host='127.0.0.1', port=5000)