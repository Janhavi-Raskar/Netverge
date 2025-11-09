from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import sqlite3
from werkzeug.utils import secure_filename
import re
from pymongo import MongoClient, errors
from collections import Counter
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Needed for flashing messages
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'log'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Database setup - SQLite as fallback
DB_PATH = os.path.join(os.path.dirname(__file__), 'logs.db')

def init_sqlite_db():
    """Initialize SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_message TEXT NOT NULL,
            priority INTEGER,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            suspicion_score INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print('SQLite database initialized successfully!')

# Initialize SQLite database
init_sqlite_db()

def get_sqlite_connection():
    """Get SQLite connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# MongoDB Atlas connection (with fallback to SQLite)
MONGO_URI = 'mongodb+srv://janhaviraskar2006:%3C7mW47Tb8_-m2KTP%3E@netverge-cluster.trpq96t.mongodb.net/?retryWrites=true&w=majority&appName=netverge-cluster'
mongo_available = False
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_db = mongo_client['netverge']
    alerts_collection = mongo_db['alerts']
    mongo_client.admin.command('ping')
    mongo_available = True
    print('Connected to MongoDB Atlas successfully!')
except Exception as e:
    print(f'MongoDB connection failed: {e}')
    print('Using SQLite as fallback database')
    alerts_collection = None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def parse_snort_log(file_path):
    entries = []
    with open(file_path, 'r') as f:
        lines = f.readlines()
    i = 0
    while i < len(lines):
        if '[**]' in lines[i]:
            alert_match = re.search(r'\] (.+) \[\*\*\]', lines[i])
            alert_message = alert_match.group(1).strip() if alert_match else ''
            priority_match = re.search(r'\[Priority: (\d+)\]', lines[i+1]) if i+1 < len(lines) else None
            priority = int(priority_match.group(1)) if priority_match else None
            if i+2 < len(lines):
                parts = lines[i+2].strip().split()
                timestamp = parts[0] if len(parts) > 0 else ''
                src_ip = parts[1] if len(parts) > 1 else ''
                dst_ip = parts[3] if len(parts) > 3 and parts[2] == '->' else ''
            else:
                timestamp = src_ip = dst_ip = ''
            entries.append({
                'alert_message': alert_message,
                'priority': priority,
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip
            })
            i += 3
        else:
            i += 1
    return entries

def compute_suspicion_scores(alerts):
    from datetime import datetime, timedelta
    # Count source IP repetitions
    src_ip_counts = {}
    for alert in alerts:
        src_ip = alert.get('src_ip', '')
        src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
    # Prepare timestamps for burst detection
    alert_times = []
    for alert in alerts:
        try:
            alert_times.append(datetime.strptime(alert.get('timestamp', ''), '%m/%d-%H:%M:%S.%f'))
        except Exception:
            alert_times.append(None)
    # Compute scores
    for i, alert in enumerate(alerts):
        score = 0
        # +5 for high priority
        if str(alert.get('priority', '')) == '1':
            score += 5
        # +3 if IP repeats
        if src_ip_counts.get(alert.get('src_ip', ''), 0) > 1:
            score += 3
        # +2 if 3+ alerts in 1 min window
        t = alert_times[i]
        if t:
            count_in_window = sum(1 for at in alert_times if at and abs((at - t).total_seconds()) <= 60)
            if count_in_window >= 3:
                score += 2
        alert['suspicion_score'] = score
    return alerts

def store_alerts_in_sqlite(entries):
    """Store alerts in SQLite database"""
    conn = get_sqlite_connection()
    cursor = conn.cursor()
    inserted_count = 0
    
    for entry in entries:
        # Check if entry already exists
        cursor.execute('''
            SELECT id FROM alerts 
            WHERE alert_message = ? AND priority = ? AND timestamp = ? 
            AND src_ip = ? AND dst_ip = ?
        ''', (
            entry['alert_message'], 
            entry['priority'], 
            entry['timestamp'], 
            entry['src_ip'], 
            entry['dst_ip']
        ))
        
        if not cursor.fetchone():
            # Insert new entry
            cursor.execute('''
                INSERT INTO alerts (alert_message, priority, timestamp, src_ip, dst_ip)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                entry['alert_message'],
                entry['priority'],
                entry['timestamp'],
                entry['src_ip'],
                entry['dst_ip']
            ))
            inserted_count += 1
    
    conn.commit()
    conn.close()
    return inserted_count

def get_alerts_from_sqlite():
    """Get all alerts from SQLite database"""
    conn = get_sqlite_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM alerts ORDER BY created_at DESC')
    rows = cursor.fetchall()
    
    alerts = []
    for row in rows:
        alert = {
            'alert_message': row['alert_message'],
            'priority': row['priority'],
            'timestamp': row['timestamp'],
            'src_ip': row['src_ip'],
            'dst_ip': row['dst_ip'],
            'suspicion_score': row['suspicion_score']
        }
        alerts.append(alert)
    
    conn.close()
    return alerts

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            print('[DEBUG] No file part in request.files')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            print('[DEBUG] No file selected for upload')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            print(f'[DEBUG] File saved to {file_path}')
            flash('File successfully uploaded')
            
            # Parse the log
            parsed_entries = parse_snort_log(file_path)
            print(f'[DEBUG] Parsed {len(parsed_entries)} entries from log file')
            
            inserted_count = 0
            
            # Try MongoDB first, fallback to SQLite
            if mongo_available and alerts_collection is not None:
                print(f'[DEBUG] Using MongoDB, attempting to store {len(parsed_entries)} alerts')
                for entry in parsed_entries:
                    query = {
                        'alert_message': entry['alert_message'],
                        'priority': entry['priority'],
                        'timestamp': entry['timestamp'],
                        'src_ip': entry['src_ip'],
                        'dst_ip': entry['dst_ip']
                    }
                    if not alerts_collection.find_one(query):
                        alerts_collection.insert_one(entry)
                        inserted_count += 1
                        print(f'[DEBUG] Inserted alert in MongoDB: {entry}')
                    else:
                        print(f'[DEBUG] Duplicate alert skipped: {entry}')
                print(f'[DEBUG] Successfully inserted {inserted_count} new alerts in MongoDB')
            else:
                # Use SQLite fallback
                print(f'[DEBUG] Using SQLite fallback, storing {len(parsed_entries)} alerts')
                inserted_count = store_alerts_in_sqlite(parsed_entries)
                print(f'[DEBUG] Successfully inserted {inserted_count} new alerts in SQLite')
            
            flash(f'{inserted_count} new alert(s) stored in database.')
            return redirect(url_for('parsed_log', filename=filename))
        else:
            flash('Only .log files are allowed!')
            print('[DEBUG] File extension not allowed')
            return redirect(request.url)
    return render_template('upload.html')

@app.route('/parsed_log')
def parsed_log():
    filename = request.args.get('filename')
    if not filename:
        flash('No file specified.')
        return redirect(url_for('upload_file'))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash('File not found.')
        return redirect(url_for('upload_file'))
    parsed_entries = parse_snort_log(file_path)
    return render_template('parsed_log.html', entries=parsed_entries, filename=filename)

@app.route('/alerts')
def show_alerts():
    # Try MongoDB first, fallback to SQLite
    if mongo_available and alerts_collection is not None:
        alerts = list(alerts_collection.find({}, {'_id': 0}))
        print(f'[DEBUG] Found {len(alerts)} alerts in MongoDB')
    else:
        # Use SQLite fallback
        alerts = get_alerts_from_sqlite()
        print(f'[DEBUG] Found {len(alerts)} alerts in SQLite')
    
    alerts = compute_suspicion_scores(alerts)
    
    # Update suspicion scores in database
    if mongo_available and alerts_collection is not None:
        # Update MongoDB
        for alert in alerts:
            alerts_collection.update_one(
                {
                    'alert_message': alert['alert_message'],
                    'priority': alert['priority'],
                    'timestamp': alert['timestamp'],
                    'src_ip': alert['src_ip'],
                    'dst_ip': alert['dst_ip']
                },
                {'$set': {'suspicion_score': alert['suspicion_score']}}
            )
    else:
        # Update SQLite
        conn = get_sqlite_connection()
        cursor = conn.cursor()
        for alert in alerts:
            cursor.execute('''
                UPDATE alerts 
                SET suspicion_score = ? 
                WHERE alert_message = ? AND priority = ? AND timestamp = ? 
                AND src_ip = ? AND dst_ip = ?
            ''', (
                alert['suspicion_score'],
                alert['alert_message'],
                alert['priority'],
                alert['timestamp'],
                alert['src_ip'],
                alert['dst_ip']
            ))
        conn.commit()
        conn.close()
    
    # Prepare data for charts
    priorities = [str(alert.get('priority', 'Unknown')) for alert in alerts]
    priority_counter = Counter(priorities)
    priority_data = {
        'labels': list(priority_counter.keys()),
        'counts': list(priority_counter.values())
    }
    alert_types = [alert.get('alert_message', 'Unknown') for alert in alerts]
    type_counter = Counter(alert_types)
    type_data = {
        'labels': list(type_counter.keys()),
        'counts': list(type_counter.values())
    }
    return render_template('alerts.html', alerts=alerts, priority_data=priority_data, type_data=type_data)

# ========== CLEAR ALL ALERTS ROUTE - Used by Clear All Alerts button in alerts.html ==========
@app.route('/clear_alerts', methods=['POST'])
def clear_alerts():
    if mongo_available and alerts_collection is not None:
        alerts_collection.delete_many({})
        print('[DEBUG] Cleared alerts from MongoDB')
    else:
        conn = get_sqlite_connection()
        cursor = conn.cursor()
        cursor.execute('DELETE FROM alerts')
        conn.commit()
        conn.close()
        print('[DEBUG] Cleared alerts from SQLite')
    return '', 204
# ========== END CLEAR ALL ALERTS ROUTE ==========

if __name__ == '__main__':
    app.run(debug=True) 
