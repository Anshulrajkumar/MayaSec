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
