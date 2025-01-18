from flask import Flask, render_template, request, redirect, url_for, send_from_directory, Response, flash, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
import os
import sqlite3
import secrets
from datetime import datetime
import mimetypes
import re
from datetime import datetime
from send2trash import send2trash
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env")
# Admin cred
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "securepassword123")


def get_public_ip():
    import requests
    
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json()['ip']
    except requests.exceptions.RequestException:
        ip = 'Unable to get IP'
    return ip

def get_local_ip():
    import socket
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10 GB max file size
ALLOWED_EXTENSIONS = {'exe', 'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mkv', 'html', 'mp3', 'wav', 'ogg', 'webm', 'webp', 'csv', 'json', 'xml', 'sql', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'log', 'md', 'rst', 'tex', 'bib', 'docx', 'xlsx', 'xls', 'pptx', 'ppt', 'odt', 'ods', 'odp', 'txt', 'csv', 'json', 'xml', 'sql', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf', 'log', 'md', 'rst', 'tex', 'bib', 'docx', 'xlsx', 'xls', 'pptx', 'ppt', 'odt', 'ods', 'odp'}
# 1 GB = 1,073,741,824 bytes

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            base_password TEXT NOT NULL,
            account_status TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS shared_files (
            shared_id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_mail TEXT NOT NULL,
            from_id INTEGER NOT NULL,
            to_mail TEXT NOT NULL,
            to_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            shared_type TEXT NOT NULL,
            expire_date TEXT NOT NULL
        )
    ''') 
    c.execute('''
        CREATE TABLE IF NOT EXISTS applied_users (
            rowid INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            base_password TEXT NOT NULL
        )
    ''')
    c.execute('SELECT COUNT(*) FROM users WHERE email = ?', (ADMIN_EMAIL,))
    if c.fetchone()[0] == 0:
        c.execute('INSERT INTO users (email, password, base_password, account_status) VALUES (?, ?, ?, ?)', 
                  (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD), ADMIN_PASSWORD, "ADMIN"))
        conn.commit()
    else:
        c.execute(
            'UPDATE users SET password = ?, base_password = ?, account_status = ? WHERE email = ?', 
            (generate_password_hash(ADMIN_PASSWORD), ADMIN_PASSWORD, "ADMIN", ADMIN_EMAIL)
        )
        conn.commit()
                
    conn.close()
    

def delete_expired_files():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute('''
        DELETE FROM shared_files
        WHERE expire_date < DATE('now')
    ''')
    
    conn.commit()
    conn.close()

def start_scheduler():
    scheduler = BackgroundScheduler()
    scheduler.add_job(delete_expired_files, 'cron', hour=0, minute=0)
    scheduler.start()

@app.before_first_request
def initialize_scheduler():
    start_scheduler()
    
    
def get_chunk_size(file_size):
    """Calculate optimal chunk size based on file size"""
    return min(1024 * 1024, file_size // 1000)  # Min of 1MB or file_size/1000

def get_range(range_header, file_size):
    """Parse Range header and return start and end positions"""
    if range_header:
        match = re.search(r'bytes=(\d+)-(\d*)', range_header)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else file_size - 1
            return start, min(end, file_size - 1)
    return 0, file_size - 1

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email
        
def get_user_folder():
    return os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    user = c.execute('SELECT id, email FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user[0], user[1])
    return None

def allowed_file(filename):
    # return True
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, email, base_password, account_status FROM users ORDER BY id')
    users = c.fetchall()
    c.execute('SELECT rowid, email FROM applied_users')
    applicants = c.fetchall()
    c.execute('SELECT shared_id, from_mail, to_mail, file_path, shared_type, expire_date FROM shared_files')
    shared_files = c.fetchall() 
    conn.close()
    return render_template('admin_dashboard.html', users=users, applicants=applicants, shared_files=shared_files)

@app.route('/accept_user/<int:user_id>', methods=['POST'])
@login_required
def accept_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM applied_users WHERE rowid = ?', (user_id,))
    applicant = c.fetchone()

    if applicant:
        c.execute('INSERT INTO users (email, password, base_password, account_status) VALUES (?, ?, ?, ?)', 
                  (applicant[1], applicant[2], applicant[3], "OK"))
        c.execute('DELETE FROM applied_users WHERE rowid = ?', (user_id,))
        conn.commit()
    conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/reject_user/<int:user_id>', methods=['POST'])
@login_required
def reject_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM applied_users WHERE rowid = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/freeze_user/<int:user_id>', methods=['POST'])
@login_required
def freeze_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    if user:
        update_query = '''
            UPDATE users
            SET account_status = ?
            WHERE id = ?
        '''
        try:
            c.execute(update_query, ("FREEZED", user_id))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error updating user: {e}")
        finally:
            conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/unfreeze_user/<int:user_id>', methods=['POST'])
@login_required
def unfreeze_user(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()

    if user:
        update_query = '''
            UPDATE users
            SET account_status = ?
            WHERE id = ?
        '''
        try:
            c.execute(update_query, ("OK", user_id))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Error updating user: {e}")
        finally:
            conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_shared_link/<int:shared_id>', methods=['POST'])
@login_required
def delete_shared_link(shared_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM shared_files WHERE shared_id = ?', (shared_id,))
    conn.commit()
    conn.close()
    
    return redirect(url_for('index'))
    
@app.route('/')
@login_required
def index():
    user_folder = get_user_folder()
    files = []
    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            filepath = os.path.join(user_folder, filename)
            files.append({
                'name': filename,
                'path': filepath.replace('\\', '/'),
                'size': os.path.getsize(filepath),
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
            })
    
    # Get list of users for sharing
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id != ? AND account_status != 'FREEZED'", (current_user.id,))
    users = c.fetchall()
    conn.close()
    
    return render_template('index.html', files=files, users=users)

@app.route('/shared_files')
@login_required
def shared():
    # Get list of users for sharing
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT shared_id, from_id, to_id, file_path, expire_date FROM shared_files WHERE to_id = ? AND expire_date >= date('now')", (current_user.id,))
    shared_files = c.fetchall()
    conn.close()
    
    files = []
    for row in shared_files:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], str(row[1]), row[3])
        if os.path.exists(filepath):
            files.append({
                'name': os.path.basename(filepath),
                'path': filepath.replace('\\', '/'),
                'size': os.path.getsize(filepath),
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath)),
                'shared_id': row[0],
                'from_id': row[1]
            })
    
    return render_template('index.html', files=files, users=[])

@app.route('/<path:path>', methods=['GET'])
@login_required
def show_directory(path):
    user_folder = get_user_folder()
    directory_path = os.path.join(user_folder, path).replace('\\', '/')
    # print("show_directory1", path, directory_path)
    
    if not os.path.exists(directory_path):
        flash("Folder not found.", "error")
        return redirect(url_for('index'))
    
    files = []
    if os.path.exists(directory_path) and os.path.isdir(directory_path):
        for filename in os.listdir(directory_path):
            filepath = os.path.join(directory_path, filename)
            files.append({
                'name': filename,
                'path': filepath.replace('\\', '/'),
                'size': os.path.getsize(filepath),
                'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
            })
        
        # Get list of users for sharing
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, email FROM users WHERE id != ? AND account_status != 'FREEZED'", (current_user.id,))
        users = c.fetchall()
        conn.close()
        
        return render_template('index.html', files=files, users=users)
    else:
        flash('Invalid folder name')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        user = c.execute('SELECT id, email, password, account_status FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if email==ADMIN_EMAIL and password==ADMIN_PASSWORD:
            login_user(User(user[0], user[1]))
            return redirect(url_for('admin_dashboard'))
        
        elif user and check_password_hash(user[2], password):
            if(user[3]=="FREEZED"):
                flash("You account is freezed please contact admin to unfreeze!!")
                return redirect(url_for('login'))
            
            login_user(User(user[0], user[1]))
            return redirect(url_for('index'))
        
        flash('Invalid email or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].lower()
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        if c.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('Email already registered')
            conn.close()
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        if c.execute('SELECT rowid FROM applied_users WHERE email = ?', (email,)).fetchone():
            flash('Email already applied once. Please contact admin!!')
            conn.close()
            return render_template('register.html')
        
        c.execute('INSERT INTO applied_users (email, password, base_password) VALUES (?, ?, ?)', (email, hashed_password, password))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    try:
        file = request.files['file']
        chunk_index = int(request.form.get('chunkIndex', 0))
        total_chunks = int(request.form.get('totalChunks', 1))
        current_path = request.form['currentPath'].replace('/', '\\')[1:]

        user_folder = get_user_folder()
        folder_path = os.path.join(user_folder, current_path)

        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

        file_path = os.path.join(folder_path, secure_filename(file.filename))

        # Write or append to the file depending on the chunk index
        with open(file_path, 'ab' if chunk_index > 0 else 'wb') as f:
            f.write(file.stream.read())

        return jsonify({
            "status": "Chunk received",
            "chunkIndex": chunk_index,
            "totalChunks": total_chunks,
            "fileName": file.filename
        }), 200
    except Exception as e:
        print(f"Error handling chunk: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    user_folder = get_user_folder()
    folder_name = request.form['folderName']
    current_path = request.form['currentPath'].replace('/', '\\')[1:]
    folder_path = os.path.join(user_folder, current_path, folder_name)
    
    try:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            flash(f'Folder "{folder_name}" created successfully!', 'success')
        else:
            flash(f'Folder "{folder_name}" already exists.', 'error')
    except Exception as e:
        flash(f'Error creating folder: {e}', 'error')
    
    return redirect(url_for('index'))

@app.route('/delete/<path:subpath>/<filename>', methods=['DELETE', 'GET', 'POST'])
@login_required
def delete_file(subpath, filename):
    if(subpath=="Server_baseIndexDirectory"):
        subpath=""
    user_folder = get_user_folder()
    file_path = os.path.join(user_folder, subpath, filename)
    
    try:
        if os.path.exists(file_path):
            if os.path.isdir(file_path):
                # import shutil
                # shutil.rmtree(file_path)
                send2trash(file_path)
            else:
                # os.remove(file_path)
                send2trash(file_path)
            return jsonify({"message": f"{filename} deleted successfully!"}), 200
        else:
            return jsonify({"error": f"{filename} not found!"}), 404
    except Exception as e:
        return jsonify({"error": "Error occurred in server"}), 500

   
@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            return send_from_directory(directory=directory, path=filename, as_attachment=True)
        else:
            return "Access denied", 403
    else:
        user_folder = get_user_folder()
        return send_from_directory(directory=user_folder, path=filepath, as_attachment=True)

@app.route('/download_view/<path:filepath>')
@login_required
def download_file_view(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
            return send_from_directory(directory=os.path.join(app.config['UPLOAD_FOLDER'], str(from_id)), path=file_path, as_attachment=True)
        else:
            return "Access denied", 403
    else:
        user_folder = get_user_folder()
        filePath = '/'.join(filepath.split('/')[1:])
        return send_from_directory(directory=user_folder, path=filePath, as_attachment=True)

@app.route('/files/<path:filename>')
@login_required
def serve_file(filename):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    if shared_id and from_id:
        # Check if the file is shared with the current user
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
        else:
            return "Access denied", 403
    else:
        file_path = os.path.join(get_user_folder(), filename)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    filetype = os.path.basename(file_path).split('.')[-1]
    if filetype not in {'mp4', 'mkv'}:
        return send_file(file_path, as_attachment=False)
    else:
        file = open(file_path, 'rb')
        file_size = os.path.getsize(file_path)
        range_header = request.headers.get('Range', None)
        if range_header:
            byte1, byte2 = parse_range_header(range_header, file_size)
            file.seek(byte1)
            data = file.read(byte2 - byte1 + 1)
            response = Response(data, status=206, content_type="video/mp4")
            response.headers.add('Content-Range', f'bytes {byte1}-{byte2}/{file_size}')
            response.headers.add('Accept-Ranges', 'bytes')
        else:
            file.seek(0)
            data = file.read()
            response = Response(data, status=200, content_type="video/mp4")
        
        file.close()
        return response

def parse_range_header(range_header, file_size):
    byte1, byte2 = 0, file_size - 1
    byte_range = range_header.strip().replace("bytes=", "")
    if "-" in byte_range:
        start, end = byte_range.split("-")
        byte1 = int(start)
        byte2 = int(end) if end else file_size - 1
    return byte1, byte2

@app.route('/stream/<path:filepath>')
def stream_video(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
        else:
            return "Access denied", 403
    else:
        file_path = os.path.join(get_user_folder(), filepath)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    file_size = os.path.getsize(file_path)
    file_type = mimetypes.guess_type(file_path)[0]
    
    return render_template('stream.html', 
                         filename=os.path.basename(filepath),
                         video_url=url_for('serve_file', filename=filepath, shared_id=shared_id, from_id=from_id),
                         file_size=file_size,
                         file_type=file_type,
                         sharing_link=filepath)

@app.route('/image/<path:filepath>')
def view_image(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id != ?", (current_user.id,))
    users = c.fetchall()
    conn.close()
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
        else:
            return "Access denied", 403
    else:
        file_path = os.path.join(get_user_folder(), filepath)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    return render_template('image.html',
                         filename=os.path.basename(filepath),
                         image_url=url_for('serve_file', filename=filepath, shared_id=shared_id, from_id=from_id),
                         users=users,
                         sharing_link=filepath)

@app.route('/audio/<path:filepath>')
def play_audio(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id != ?", (current_user.id,))
    users = c.fetchall()
    conn.close()
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
        else:
            return "Access denied", 403
    else:
        file_path = os.path.join(get_user_folder(), filepath)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    return render_template('audio.html',
                         filename=os.path.basename(filepath),
                         audio_url=url_for('serve_file', filename=filepath, shared_id=shared_id, from_id=from_id),
                         users=users,
                         sharing_link=filepath)

@app.route('/pdf/<path:filepath>')
def view_pdf(filepath):
    shared_id = request.args.get('shared_id')
    from_id = request.args.get('from_id')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id != ?", (current_user.id,))
    users = c.fetchall()
    conn.close()
    
    if shared_id and from_id:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''SELECT file_path FROM shared_files 
                    WHERE shared_id = ? AND from_id = ? AND to_id = ? AND expire_date >= date('now')''', 
                    (shared_id, from_id, current_user.id))
        shared_file = c.fetchone()
        conn.close()
        
        if shared_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(from_id), shared_file[0])
        else:
            return "Access denied", 403
    else:
        file_path = os.path.join(get_user_folder(), filepath)
    
    if not os.path.exists(file_path):
        return "File not found", 404
        
    return render_template('pdf.html',
                         filename=os.path.basename(filepath),
                         file_url=url_for('serve_file', filename=filepath, shared_id=shared_id, from_id=from_id),
                         users=users,
                         sharing_link=filepath)


@app.route('/share_file', methods=['POST'])
@login_required
def share_file():
    try:
        data = request.get_json()
        # Extract the file path and shared data
        file_path = data.get('file_path')
        users_data = data.get('shared_data')

        print(file_path, users_data)
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        for user in users_data:
            exists = c.execute('''SELECT shared_id FROM shared_files 
                         WHERE from_mail = ? AND from_id = ? AND to_mail = ? AND to_id = ? AND file_path = ?''', 
                         (current_user.email, current_user.id, user["email"], user["id"], file_path,)).fetchone()
            if exists:
                # Update sharing record
                c.execute(
                    'UPDATE shared_files SET shared_type = ?, expire_date = ? WHERE shared_id = ?', 
                    ("READ", user["expire_date"], exists[0])
                )
            else:
                # Insert sharing record
                c.execute('''INSERT INTO shared_files 
                            (from_mail, from_id, to_mail, to_id, file_path, shared_type, expire_date) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                        (current_user.email, current_user.id, user["email"], user["id"], file_path, "READ", user["expire_date"]))
        
        conn.commit()
        conn.close()
        return jsonify({"message": "File shared successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    init_db()
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    from waitress import serve
    port = 5000
    print("Hosting in current system use below address")
    print(f"Running on http://127.0.0.1:{port} \n")
    print("Hosting locally use below address")
    print(f"Running on http://{get_local_ip()}:{port} \n")
    print("Hosting externally use below address")
    print(f"Running on http://{get_public_ip()}:{port}")
    
    # serve(app, host='0.0.0.0', port=port)
    app.run(host="0.0.0.0", port=5000, debug=True)