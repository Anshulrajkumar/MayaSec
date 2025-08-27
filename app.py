from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Import PostgreSQL Security Monitor
try:
    from pg_security_monitor import PostgreSQLSecurityMonitor
    security_monitor = PostgreSQLSecurityMonitor()
    SECURITY_ENABLED = True
    print("✅ PostgreSQL Security monitor loaded successfully")
except Exception as e:
    print(f"⚠️ PostgreSQL Security monitor not available: {e}")
    SECURITY_ENABLED = False

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    user_agent = request.headers.get('User-Agent', '')
    
    if SECURITY_ENABLED:
        # Analyze the login attempt with PostgreSQL monitoring
        result = security_monitor.analyze_login_attempt(
            ip_address=ip_address,
            username=username,
            password=password,
            user_agent=user_agent,
            timestamp=datetime.now()
        )
        
        if result['action'] == 'redirect_to_honeypot':
            return redirect(url_for('honeypot_login'))
        elif result['action'] == 'block':
            return "Access denied. Your IP has been blocked due to suspicious activity.", 403
        elif result['action'] == 'sql_injection_detected':
            return "Invalid request detected. Security incident reported.", 400
    
    # Check actual credentials
    if username == 'admin' and password == 'secure_password':
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error='Invalid credentials')

@app.route('/honeypot-login')
def honeypot_login():
    return render_template('honeypot_login.html')

@app.route('/honeypot-submit', methods=['POST'])
def honeypot_submit():
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if SECURITY_ENABLED:
        security_monitor.log_honeypot_interaction(ip_address, username, password)
    
    # Keep attacker engaged
    import time
    time.sleep(2)  # Simulate processing
    return render_template('honeypot_login.html', error='Authentication failed. Please try again.')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/security-report')
def security_report():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    if SECURITY_ENABLED:
        report = security_monitor.generate_daily_report()
        return jsonify(report)
    else:
        return jsonify({'error': 'Security monitoring not available'})

@app.route('/security-logs')
def security_logs():
    """View detailed security audit logs"""
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    if not SECURITY_ENABLED:
        return "Security monitoring disabled"
    
    conn = security_monitor.get_db_connection()
    if not conn:
        return "Database connection failed"
    
    try:
        cursor = conn.cursor()
        
        # Get recent login attempts with details
        cursor.execute('''
            SELECT ip_address, username, user_agent, timestamp, threat_level, attempt_result
            FROM login_attempts 
            ORDER BY timestamp DESC 
            LIMIT 100
        ''')
        attempts = cursor.fetchall()
        
        # Get security actions
        cursor.execute('''
            SELECT ip_address, action_type, reason, timestamp 
            FROM security_actions 
            ORDER BY timestamp DESC 
            LIMIT 50
        ''')
        actions = cursor.fetchall()
        
        # Get honeypot interactions
        cursor.execute('''
            SELECT ip_address, username, timestamp
            FROM honeypot_interactions 
            ORDER BY timestamp DESC 
            LIMIT 30
        ''')
        honeypot_data = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return render_template('security_logs.html', 
                             attempts=attempts, 
                             actions=actions, 
                             honeypot_data=honeypot_data)
    except Exception as e:
        return f"Error loading logs: {e}"

@app.route('/live-stats')
def live_stats():
    """Get real-time security statistics"""
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    if not SECURITY_ENABLED:
        return jsonify({'error': 'Security monitoring disabled'})
    
    conn = security_monitor.get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'})
    
    try:
        cursor = conn.cursor()
        
        # Get stats from last 24 hours
        cursor.execute('''
            SELECT 
                COUNT(*) as total_attempts,
                COUNT(CASE WHEN threat_level > 7 THEN 1 END) as high_threats,
                COUNT(DISTINCT ip_address) as unique_ips,
                AVG(threat_level) as avg_threat_level
            FROM login_attempts 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
        ''')
        stats = cursor.fetchone()
        
        # Get top attacking IPs
        cursor.execute('''
            SELECT ip_address, COUNT(*) as attempts
            FROM login_attempts 
            WHERE timestamp > NOW() - INTERVAL '24 hours'
            GROUP BY ip_address
            ORDER BY attempts DESC 
            LIMIT 5
        ''')
        top_ips = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'total_attempts_24h': stats[0] or 0,
            'high_threats_24h': stats[1] or 0,
            'unique_ips_24h': stats[2] or 0,
            'avg_threat_level': round(float(stats[3]) if stats[3] else 0, 2),
            'top_attacking_ips': [{'ip': ip[0], 'attempts': ip[1]} for ip in top_ips],
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': f'Error loading stats: {e}'})

# Test endpoint
@app.route('/test')
def test():
    return jsonify({
        'status': 'working',
        'message': 'Flask app with PostgreSQL security monitoring!',
        'timestamp': datetime.now().isoformat(),
        'security_enabled': SECURITY_ENABLED
    })

if __name__ == '__main__':
    app.run(debug=False)
