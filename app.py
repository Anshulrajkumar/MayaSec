from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

try:
    from security_monitor import SecurityMonitor
    security_monitor = SecurityMonitor()
    SECURITY_ENABLED = True
    print("✅ Security monitor loaded successfully")
except ImportError as e:
    print(f"⚠️  Security monitor not available: {e}")
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
            return "Access denied. Your IP has been blocked.", 403
        elif result['action'] == 'sql_injection_detected':
            return "Invalid request detected. Incident reported.", 400
    
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
    return render_template('honeypot_login.html', error='Server temporarily unavailable. Please try again.')

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

if __name__ == '__main__':
    print("🚀 Starting Adaptive Security System...")
    if SECURITY_ENABLED:
        import threading
        threading.Thread(target=security_monitor.start_monitoring, daemon=True).start()
        print("🛡️  Security monitoring started")
    app.run(debug=False, host='0.0.0.0', port=5000)
    print("🔒 Security system running on http://localhost:5000")
