from flask import Flask, render_template, request, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)

# Database configuration
DATABASE = '../security_logs.db'

def get_db_connection():
    """Create database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # This allows us to access columns by name
    return conn

def init_db():
    """Initialize database with sample data if it doesn't exist"""
    if not os.path.exists(DATABASE):
        conn = get_db_connection()
        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                attempt_result TEXT NOT NULL,
                threat_level TEXT NOT NULL
            )
        ''')
        
        # Sample data based on your screenshot
        sample_data = [
            (1, '127.0.0.1', 'admin', '019e9609bcc8c99534846d9c29891fbfe51927799110984...', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit...', '2025-08-28 19:04:44.504290', 'FAILED', 'HIGH'),
            (2, '127.0.0.1', 'admin', 'b27dfc00528b59c53de1183a1910ee7dd9d084724fb995...', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit...', '2025-08-28 19:04:59.973178', 'FAILED', 'HIGH'),
            (3, '127.0.0.1', 'etyuyt', 'b3ec36005f38fb3dc48eb176768cdbd5e5f287296078c...', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit...', '2025-08-28 19:07:30.692322', 'FAILED', 'MEDIUM'),
            (4, '127.0.0.1', 'admin', 'f61a20da9eaa68a9f06dbc1710b10ef0a67208b2059b1f5...', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit...', '2025-08-28 23:45:25.535141', 'FAILED', 'HIGH'),
            (5, '127.0.0.1', 'admin', 'ff21f2ec5c6a2e9ef6b61c958ed701c327469190a18075fd...', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit...', '2025-08-28 23:45:33.088106', 'FAILED', 'HIGH'),
        ]
        
        conn.executemany('''
            INSERT INTO login_attempts 
            (id, ip_address, username, password_hash, user_agent, timestamp, attempt_result, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', sample_data)
        
        conn.commit()
        conn.close()

@app.route('/')
def index():
    """Main page route"""
    return render_template('index.html')

@app.route('/api/data')
def get_data():
    """API endpoint to get paginated data"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '')
    threat_filter = request.args.get('threat_level', '')
    result_filter = request.args.get('attempt_result', '')
    
    conn = get_db_connection()
    
    # Build query with filters
    query = "SELECT * FROM login_attempts WHERE 1=1"
    params = []
    
    if search:
        query += " AND (username LIKE ? OR ip_address LIKE ? OR user_agent LIKE ?)"
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param])
    
    if threat_filter:
        query += " AND threat_level = ?"
        params.append(threat_filter)
    
    if result_filter:
        query += " AND attempt_result = ?"
        params.append(result_filter)
    
    # Count total records
    count_query = f"SELECT COUNT(*) FROM ({query})"
    total_count = conn.execute(count_query, params).fetchone()[0]
    
    # Add pagination
    query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])
    
    rows = conn.execute(query, params).fetchall()
    conn.close()
    
    # Convert to dict for JSON response
    data = []
    for row in rows:
        data.append({
            'id': row['id'],
            'ip_address': row['ip_address'],
            'username': row['username'],
            'password_hash': row['password_hash'][:20] + '...' if len(row['password_hash']) > 20 else row['password_hash'],
            'user_agent': row['user_agent'][:50] + '...' if len(row['user_agent']) > 50 else row['user_agent'],
            'timestamp': row['timestamp'],
            'attempt_result': row['attempt_result'],
            'threat_level': row['threat_level']
        })
    
    return jsonify({
        'data': data,
        'total': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': (total_count + per_page - 1) // per_page
    })

@app.route('/api/stats')
def get_stats():
    """API endpoint to get statistics"""
    conn = get_db_connection()
    
    # Get threat level stats
    threat_stats = conn.execute('''
        SELECT threat_level, COUNT(*) as count 
        FROM login_attempts 
        GROUP BY threat_level
    ''').fetchall()
    
    # Get attempt result stats
    result_stats = conn.execute('''
        SELECT attempt_result, COUNT(*) as count 
        FROM login_attempts 
        GROUP BY attempt_result
    ''').fetchall()
    
    # Get recent activity (last 24 hours)
    recent_activity = conn.execute('''
        SELECT COUNT(*) as count 
        FROM login_attempts 
        WHERE datetime(timestamp) > datetime('now', '-1 day')
    ''').fetchone()
    
    conn.close()
    
    return jsonify({
        'threat_stats': [dict(row) for row in threat_stats],
        'result_stats': [dict(row) for row in result_stats],
        'recent_activity': recent_activity['count']
    })

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
