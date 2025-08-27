from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Disable security monitor temporarily
SECURITY_ENABLED = False

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # Simple credential check without security monitoring
    if username == 'admin' and password == 'secure_password':
        session['logged_in'] = True
        return redirect(url_for('dashboard'))
    else:
        return render_template('login.html', error='Invalid credentials')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/security-report')
def security_report():
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return jsonify({'message': 'Security monitoring temporarily disabled'})

# Test endpoint
@app.route('/test')
def test():
    return jsonify({
        'status': 'working',
        'message': 'Flask app deployed successfully on Vercel!',
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    app.run(debug=False)
