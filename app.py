from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
import os
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Simple in-memory security monitoring (works on Vercel)
class SimpleSecurityMonitor:
    def __init__(self):
        self.failed_attempts = defaultdict(list)
        self.blacklisted_ips = set()
        self.security_events = []
        
    def analyze_login_attempt(self, ip_address, username, password, user_agent, timestamp):
        # Track failed attempts
        self.failed_attempts[ip_address].append(timestamp)
        
        # Clean old attempts (older than 1 hour)
        cutoff_time = timestamp - timedelta(hours=1)
        self.failed_attempts[ip_address] = [
            t for t in self.failed_attempts[ip_address] if t > cutoff_time
        ]
        
        attempt_count = len(self.failed_attempts[ip_address])
        
        # Log the event
        self.security_events.append({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': ip_address,
            'username': username,
            'user_agent': user_agent[:50] + '...' if len(user_agent) > 50 else user_agent,
            'event_type': 'FAILED_LOGIN',
            'details': f'Attempt {attempt_count}'
        })
        
        # Keep only last 100 events
        if len(self.security_events) > 100:
            self.security_events = self.security_events[-100:]
        
        # Check for SQL injection
        dangerous_patterns = ["'", "union", "select", "drop", "delete", "--", "/*"]
        if any(pattern in username.lower() or pattern in password.lower() for pattern in dangerous_patterns):
            self.security_events.append({
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': ip_address,
                'username': username,
                'user_agent': user_agent[:50] + '...' if len(user_agent) > 50 else user_agent,
                'event_type': 'SQL_INJECTION_DETECTED',
                'details': 'Dangerous patterns detected'
            })
            return {'action': 'sql_injection_detected', 'reason': 'SQL injection attempt'}
        
        # Redirect to honeypot after 5 attempts
        if attempt_count >= 5:
            self.security_events.append({
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': ip_address,
                'username': username,
                'user_agent': user_agent[:50] + '...' if len(user_agent) > 50 else user_agent,
                'event_type': 'HONEYPOT_REDIRECT',
                'details': f'{attempt_count} failed attempts'
            })
            return {'action': 'redirect_to_honeypot', 'reason': f'{attempt_count} failed attempts'}
        
        return {'action': 'legitimate', 'attempt_count': attempt_count}
    
    def log_honeypot_interaction(self, ip_address, username, password):
        self.security_events.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'ip_address': ip_address,
            'username': username,
            'user_agent': 'Honeypot',
            'event_type': 'HONEYPOT_INTERACTION',
            'details': f'Username: {username}'
        })
        print(f"🍯 HONEYPOT: {ip_address} tried {username}")
    
    def get_security_events(self):
        return self.security_events
    
    def get_daily_report(self):
        return {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'total_events': len(self.security_events),
            'event_types': {},
            'recent_events': self.security_events[-10:] if self.security_events else []
        }

# Initialize security monitor
security_monitor = SimpleSecurityMonitor()
SECURITY_ENABLED = True

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
        from datetime import timedelta
        result = security_monitor.analyze_login_attempt(
            ip_address=ip_address,
            username=username,
            password=password,
            user_agent=user_agent,
            timestamp=datetime.now()
        )
        
        if result['action'] == 'redirect_to_honeypot':
            return redirect(url_for('honeypot_login'))
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
    
    return render_template('honeypot_login.html', error='Authentication failed. Please try again.')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/security-logs')
def security_logs():
    """View detailed security audit logs"""
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    events = security_monitor.get_security_events()
    return render_template('security_logs.html', events=events)

@app.route('/security-report')
def security_report():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    
    report = security_monitor.get_daily_report()
    return jsonify(report)

@app.route('/test')
def test():
    return jsonify({
        'status': 'working',
        'message': 'Flask app with in-memory security monitoring!',
        'timestamp': datetime.now().isoformat(),
        'security_enabled': SECURITY_ENABLED,
        'total_events': len(security_monitor.get_security_events())
    })

if __name__ == '__main__':
    app.run(debug=False)
