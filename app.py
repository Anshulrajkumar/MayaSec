from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Import with error handling
try:
    from security_monitor import SecurityMonitor
    security_monitor = SecurityMonitor()
    SECURITY_ENABLED = True
    print("✅ Security monitor loaded successfully")
except ImportError as e:
    print(f"⚠️  Security monitor not available: {e}")
    SECURITY_ENABLED = False

# Your existing routes...
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
        # Analyze the login attempt
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
    
    # Check actual credentials
    if username == 'admin' and password == 'secure_password':
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error='Invalid credentials')

# ... rest of your routes

# For Vercel deployment
if __name__ == '__main__':
    app.run(debug=False)
