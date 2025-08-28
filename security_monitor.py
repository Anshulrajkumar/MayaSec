import sqlite3
import json
import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time
import smtplib
import logging

# Fix for email import issues
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    EMAIL_AVAILABLE = True
except ImportError:
    print("Warning: Email functionality not available. Alerts will be logged only.")
    EMAIL_AVAILABLE = False

class SecurityMonitor:
    def __init__(self):
        self.init_database()
        self.failed_attempts = defaultdict(list)
        self.blacklisted_ips = set()
        self.whitelisted_ips = set()
        self.sql_injection_patterns = [
            r"(\bUNION\b.*\bSELECT\b)",
            r"(\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
            r"(\bINSERT\b.*\bINTO\b)",
            r"(\bDROP\b.*\bTABLE\b)",
            r"(\bDELETE\b.*\bFROM\b)",
            r"(--|#|/\*|\*/)",
            r"(\bOR\b.*=.*)",
            r"(\bAND\b.*=.*)",
            r"('\s*OR\s*'1'\s*=\s*'1)",
            r"('\s*OR\s*1\s*=\s*1)",
            r"(\bxp_cmdshell\b)",
            r"(\bsp_executesql\b)"
        ]
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onload\s*=",
            r"onerror\s*=",
            r"onclick\s*="
        ]
        
        self.setup_logging()
        
    def setup_logging(self):
        self.security_logger = logging.getLogger('SecurityMonitor')
        self.security_logger.setLevel(logging.INFO)
        handler = logging.FileHandler('security_monitor.log')
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.security_logger.addHandler(handler)
        
    def init_database(self):
        self.conn = sqlite3.connect('security_logs.db', check_same_thread=False)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    username TEXT,
                    password_hash TEXT,
                    user_agent TEXT,
                    timestamp DATETIME,
                    attempt_result TEXT,
                    threat_level INTEGER
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS security_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    action_type TEXT,
                    reason TEXT,
                    timestamp DATETIME,
                    automated BOOLEAN
                )
            ''')
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS honeypot_interactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    username TEXT,
                    password_hash TEXT,
                    interaction_data TEXT,
                    timestamp DATETIME
                )
            ''')
            self.conn.commit()
    
    def analyze_login_attempt(self, ip_address, username, password, user_agent, timestamp):
        if ip_address in self.blacklisted_ips:
            self.log_security_action(ip_address, 'BLOCKED', 'IP in blacklist', True)
            return {'action': 'block', 'reason': 'Blacklisted IP'}
        
        if self.detect_sql_injection(username) or self.detect_sql_injection(password):
            self.handle_sql_injection(ip_address, username, password)
            return {'action': 'sql_injection_detected', 'reason': 'SQL injection attempt'}
        
        if self.detect_xss(username) or self.detect_xss(password):
            self.handle_xss_attempt(ip_address, username, password)
            return {'action': 'suspicious_input', 'reason': 'XSS attempt detected'}
        
        self.failed_attempts[ip_address].append(timestamp)
        cutoff_time = timestamp - timedelta(hours=1)
        self.failed_attempts[ip_address] = [
            t for t in self.failed_attempts[ip_address] if t > cutoff_time
        ]
        attempt_count = len(self.failed_attempts[ip_address])
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        threat_level = self.calculate_threat_level(ip_address, username, password, user_agent)
        with self.lock:
            self.conn.execute('''
                INSERT INTO login_attempts 
                (ip_address, username, password_hash, user_agent, timestamp, attempt_result, threat_level)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (ip_address, username, password_hash, user_agent, timestamp, 'FAILED', threat_level))
            self.conn.commit()
        if attempt_count >= 6:
            self.log_security_action(ip_address, 'HONEYPOT_REDIRECT', f'{attempt_count} failed attempts', True)
            return {'action': 'redirect_to_honeypot', 'reason': f'{attempt_count} failed attempts'}
        elif threat_level > 7:
            self.blacklist_ip(ip_address, f'High threat level: {threat_level}')
            return {'action': 'block', 'reason': 'High threat level detected'}
        return {'action': 'legitimate', 'threat_level': threat_level}
    
    def detect_sql_injection(self, input_string):
        if not input_string:
            return False
        input_lower = input_string.lower()
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        return False

    def detect_xss(self, input_string):
        if not input_string:
            return False
        for pattern in self.xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
    
    def calculate_threat_level(self, ip_address, username, password, user_agent):
        threat_level = 0
        suspicious_usernames = ['admin', 'administrator', 'root', 'test', 'guest']
        if username.lower() in suspicious_usernames:
            threat_level += 2
        common_passwords = ['password', '123456', 'admin', 'test', 'guest']
        if password.lower() in common_passwords:
            threat_level += 3
        if not user_agent or 'bot' in user_agent.lower():
            threat_level += 2
        special_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        for char in special_chars:
            if char in username or char in password:
                threat_level += 1
        recent_attempts = len(self.failed_attempts.get(ip_address, []))
        threat_level += min(recent_attempts, 5)
        return min(threat_level, 10)
    
    def handle_sql_injection(self, ip_address, username, password):
        self.blacklist_ip(ip_address, 'SQL injection attempt detected')
        self.report_to_hq({
            'type': 'SQL_INJECTION',
            'ip': ip_address,
            'username': username,
            'timestamp': datetime.now().isoformat(),
            'severity': 'HIGH'
        })
        with self.lock:
            self.conn.execute('''
                INSERT INTO security_actions 
                (ip_address, action_type, reason, timestamp, automated)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_address, 'SQL_INJECTION_DETECTED', f'Username: {username}', datetime.now(), True))
            self.conn.commit()
    
    def handle_xss_attempt(self, ip_address, username, password):
        self.log_security_action(ip_address, 'XSS_DETECTED', f'Username: {username}', True)
    
    def blacklist_ip(self, ip_address, reason):
        self.blacklisted_ips.add(ip_address)
        self.log_security_action(ip_address, 'BLACKLISTED', reason, True)
        self.security_logger.warning(f"IP {ip_address} blacklisted: {reason}")
    
    def whitelist_ip(self, ip_address, reason):
        self.whitelisted_ips.add(ip_address)
        if ip_address in self.blacklisted_ips:
            self.blacklisted_ips.remove(ip_address)
        self.log_security_action(ip_address, 'WHITELISTED', reason, False)
        self.security_logger.info(f"IP {ip_address} whitelisted: {reason}")
    
    def log_security_action(self, ip_address, action_type, reason, automated):
        with self.lock:
            self.conn.execute('''
                INSERT INTO security_actions 
                (ip_address, action_type, reason, timestamp, automated)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_address, action_type, reason, datetime.now(), automated))
            self.conn.commit()
        self.security_logger.info(f"Security action: {action_type} for {ip_address} - {reason}")
    
    def log_honeypot_interaction(self, ip_address, username, password):
        password_hash = hashlib.sha256(password.encode()).hexdigest() if password else ''
        interaction_data = json.dumps({
            'username': username,
            'password_length': len(password) if password else 0,
            'contains_special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)) if password else False
        })
        with self.lock:
            self.conn.execute('''
                INSERT INTO honeypot_interactions 
                (ip_address, username, password_hash, interaction_data, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (ip_address, username, password_hash, interaction_data, datetime.now()))
            self.conn.commit()
        self.security_logger.warning(f"Honeypot interaction from {ip_address}: {username}")
    
    def report_to_hq(self, incident_data):
        self.security_logger.critical(f"SECURITY ALERT: {json.dumps(incident_data, indent=2)}")
        print(f"🚨 SECURITY ALERT: {incident_data['type']} from {incident_data['ip']}")
    
    def generate_daily_report(self):
        yesterday = datetime.now() - timedelta(days=1)
        with self.lock:
            cursor = self.conn.execute('''
                SELECT COUNT(*), AVG(threat_level) 
                FROM login_attempts 
                WHERE timestamp > ?
            ''', (yesterday,))
            attempt_stats = cursor.fetchone()
            
            cursor = self.conn.execute('''
                SELECT action_type, COUNT(*) 
                FROM security_actions 
                WHERE timestamp > ? 
                GROUP BY action_type
            ''', (yesterday,))
            actions = dict(cursor.fetchall())
            
            cursor = self.conn.execute('''
                SELECT COUNT(*) 
                FROM honeypot_interactions 
                WHERE timestamp > ?
            ''', (yesterday,))
            honeypot_interactions = cursor.fetchone()[0]
        report = {
            'date': datetime.now().strftime('%Y-%m-%d'),
            'total_login_attempts': attempt_stats[0] or 0,
            'average_threat_level': round(attempt_stats[1] or 0, 2),
            'security_actions': actions,
            'honeypot_interactions': honeypot_interactions,
            'blacklisted_ips': list(self.blacklisted_ips),
            'whitelisted_ips': list(self.whitelisted_ips),
            'recommendations': self.generate_recommendations()
        }
        self.security_logger.info(f"Daily report generated: {report['total_login_attempts']} attempts, {len(self.blacklisted_ips)} blacklisted IPs")
        return report
    
    def generate_recommendations(self):
        recommendations = []
        with self.lock:
            recent_attempts = self.conn.execute('''
                SELECT ip_address, COUNT(*) as attempt_count
                FROM login_attempts 
                WHERE timestamp > datetime('now', '-24 hours')
                GROUP BY ip_address
                ORDER BY attempt_count DESC
                LIMIT 10
            ''').fetchall()
        if recent_attempts:
            for ip, count in recent_attempts:
                if count > 10:
                    recommendations.append(f"Consider blocking IP {ip} - {count} attempts in 24h")
        if len(self.blacklisted_ips) > 50:
            recommendations.append("High number of blacklisted IPs - consider reviewing firewall rules")
        return recommendations
    
    def start_monitoring(self):
        self.security_logger.info("Starting security monitoring background process")
        while True:
            try:
                old_date = datetime.now() - timedelta(days=30)
                with self.lock:
                    self.conn.execute('DELETE FROM login_attempts WHERE timestamp < ?', (old_date,))
                    self.conn.execute('DELETE FROM security_actions WHERE timestamp < ?', (old_date,))
                    self.conn.commit()
                current_time = datetime.now()
                if current_time.hour == 8 and current_time.minute == 0:  # 8 AM daily
                    report = self.generate_daily_report()
                    # FIXED LINE - Changed quotes to avoid escape sequence conflicts
                    report_filename = f"daily_report_{current_time.strftime('%Y%m%d')}.json"
                    with open(report_filename, 'w') as f:
                        json.dump(report, f, indent=2)
                    self.security_logger.info(f"Daily report saved: {report_filename}")
                time.sleep(60)
            except Exception as e:
                self.security_logger.error(f"Monitoring error: {e}")
                time.sleep(60)
