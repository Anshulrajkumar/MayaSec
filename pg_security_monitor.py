import psycopg2
from psycopg2.extras import DictCursor
import json
import re
import hashlib
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time
import logging
import os

class PostgreSQLSecurityMonitor:
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
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup security logging"""
        self.security_logger = logging.getLogger('PostgreSQLSecurityMonitor')
        self.security_logger.setLevel(logging.INFO)
        
    def get_db_connection(self):
        """Get PostgreSQL connection"""
        try:
            DATABASE_URL = os.environ.get('POSTGRES_URL')
            if not DATABASE_URL:
                raise Exception("POSTGRES_URL environment variable not found")
            
            # Fix the connection string for SQLAlchemy compatibility
            if DATABASE_URL.startswith('postgres://'):
                DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
            
            return psycopg2.connect(DATABASE_URL, sslmode='require')
        except Exception as e:
            print(f"Database connection error: {e}")
            return None
        
    def init_database(self):
        """Initialize PostgreSQL database tables"""
        conn = self.get_db_connection()
        if not conn:
            return False
            
        try:
            cursor = conn.cursor()
            
            # Create login_attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT,
                    username TEXT,
                    password_hash TEXT,
                    user_agent TEXT,
                    timestamp TIMESTAMP,
                    attempt_result TEXT,
                    threat_level INTEGER
                )
            ''')
            
            # Create security_actions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_actions (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT,
                    action_type TEXT,
                    reason TEXT,
                    timestamp TIMESTAMP,
                    automated BOOLEAN
                )
            ''')
            
            # Create honeypot_interactions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS honeypot_interactions (
                    id SERIAL PRIMARY KEY,
                    ip_address TEXT,
                    username TEXT,
                    password_hash TEXT,
                    interaction_data TEXT,
                    timestamp TIMESTAMP
                )
            ''')
            
            conn.commit()
            cursor.close()
            conn.close()
            print("✅ PostgreSQL database initialized successfully")
            return True
            
        except Exception as e:
            print(f"Database initialization error: {e}")
            if conn:
                conn.close()
            return False
    
    def analyze_login_attempt(self, ip_address, username, password, user_agent, timestamp):
        """Main analysis function for login attempts"""
        
        # Check if IP is blacklisted
        if ip_address in self.blacklisted_ips:
            self.log_security_action(ip_address, 'BLOCKED', 'IP in blacklist', True)
            return {'action': 'block', 'reason': 'Blacklisted IP'}
        
        # Check for SQL injection
        if self.detect_sql_injection(username) or self.detect_sql_injection(password):
            self.handle_sql_injection(ip_address, username, password)
            return {'action': 'sql_injection_detected', 'reason': 'SQL injection attempt'}
        
        # Check for XSS attempts
        if self.detect_xss(username) or self.detect_xss(password):
            self.handle_xss_attempt(ip_address, username, password)
            return {'action': 'suspicious_input', 'reason': 'XSS attempt detected'}
        
        # Count failed attempts
        self.failed_attempts[ip_address].append(timestamp)
        
        # Clean old attempts (older than 1 hour)
        cutoff_time = timestamp - timedelta(hours=1)
        self.failed_attempts[ip_address] = [
            t for t in self.failed_attempts[ip_address] if t > cutoff_time
        ]
        
        attempt_count = len(self.failed_attempts[ip_address])
        
        # Log the attempt
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        threat_level = self.calculate_threat_level(ip_address, username, password, user_agent)
        
        self.log_login_attempt(ip_address, username, password_hash, user_agent, timestamp, threat_level)
        
        # Determine action based on attempt count and threat level
        if attempt_count >= 6:
            self.log_security_action(ip_address, 'HONEYPOT_REDIRECT', f'{attempt_count} failed attempts', True)
            return {'action': 'redirect_to_honeypot', 'reason': f'{attempt_count} failed attempts'}
        elif threat_level > 7:
            self.blacklist_ip(ip_address, f'High threat level: {threat_level}')
            return {'action': 'block', 'reason': 'High threat level detected'}
        
        return {'action': 'legitimate', 'threat_level': threat_level}
    
    def log_login_attempt(self, ip_address, username, password_hash, user_agent, timestamp, threat_level):
        """Log login attempt to PostgreSQL"""
        conn = self.get_db_connection()
        if not conn:
            return
            
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_attempts 
                (ip_address, username, password_hash, user_agent, timestamp, attempt_result, threat_level)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            ''', (ip_address, username, password_hash, user_agent, timestamp, 'FAILED', threat_level))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error logging login attempt: {e}")
            if conn:
                conn.close()
    
    def detect_sql_injection(self, input_string):
        """Detect SQL injection patterns"""
        if not input_string:
            return False
            
        input_lower = input_string.lower()
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, input_lower, re.IGNORECASE):
                return True
        return False
    
    def detect_xss(self, input_string):
        """Detect XSS patterns"""
        if not input_string:
            return False
            
        for pattern in self.xss_patterns:
            if re.search(pattern, input_string, re.IGNORECASE):
                return True
        return False
    
    def calculate_threat_level(self, ip_address, username, password, user_agent):
        """Calculate threat level based on various factors"""
        threat_level = 0
        
        # Check for common attack patterns
        suspicious_usernames = ['admin', 'administrator', 'root', 'test', 'guest']
        if username and username.lower() in suspicious_usernames:
            threat_level += 2
        
        # Check for common passwords
        common_passwords = ['password', '123456', 'admin', 'test', 'guest']
        if password and password.lower() in common_passwords:
            threat_level += 3
        
        # Check user agent
        if not user_agent or 'bot' in user_agent.lower():
            threat_level += 2
        
        # Check for special characters that might indicate injection
        special_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        for char in special_chars:
            if (username and char in username) or (password and char in password):
                threat_level += 1
        
        # Check recent failed attempts from this IP
        recent_attempts = len(self.failed_attempts.get(ip_address, []))
        threat_level += min(recent_attempts, 5)
        
        return min(threat_level, 10)  # Cap at 10
    
    def handle_sql_injection(self, ip_address, username, password):
        """Handle detected SQL injection attempt"""
        self.blacklist_ip(ip_address, 'SQL injection attempt detected')
        self.log_security_action(ip_address, 'SQL_INJECTION_DETECTED', f'Username: {username}', True)
        print(f"🚨 SQL INJECTION DETECTED from {ip_address}: {username}")
    
    def handle_xss_attempt(self, ip_address, username, password):
        """Handle detected XSS attempt"""
        self.log_security_action(ip_address, 'XSS_DETECTED', f'Username: {username}', True)
        print(f"🚨 XSS ATTEMPT DETECTED from {ip_address}: {username}")
    
    def blacklist_ip(self, ip_address, reason):
        """Add IP to blacklist"""
        self.blacklisted_ips.add(ip_address)
        self.log_security_action(ip_address, 'BLACKLISTED', reason, True)
        print(f"🚫 IP BLACKLISTED: {ip_address} - {reason}")
    
    def log_security_action(self, ip_address, action_type, reason, automated):
        """Log security actions to PostgreSQL"""
        conn = self.get_db_connection()
        if not conn:
            return
            
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_actions 
                (ip_address, action_type, reason, timestamp, automated)
                VALUES (%s, %s, %s, %s, %s)
            ''', (ip_address, action_type, reason, datetime.now(), automated))
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            print(f"Error logging security action: {e}")
            if conn:
                conn.close()
    
    def log_honeypot_interaction(self, ip_address, username, password):
        """Log honeypot interactions to PostgreSQL"""
        conn = self.get_db_connection()
        if not conn:
            print(f"🍯 HONEYPOT (not logged): {ip_address} - {username}")
            return
            
        try:
            password_hash = hashlib.sha256(password.encode()).hexdigest() if password else ''
            interaction_data = json.dumps({
                'username': username,
                'password_length': len(password) if password else 0,
                'contains_special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)) if password else False
            })
            
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO honeypot_interactions 
                (ip_address, username, password_hash, interaction_data, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            ''', (ip_address, username, password_hash, interaction_data, datetime.now()))
            conn.commit()
            cursor.close()
            conn.close()
            print(f"🍯 HONEYPOT LOGGED: {ip_address} - {username}")
        except Exception as e:
            print(f"Error logging honeypot interaction: {e}")
            if conn:
                conn.close()
    
    def generate_daily_report(self):
        """Generate daily security report from PostgreSQL"""
        conn = self.get_db_connection()
        if not conn:
            return {'error': 'Database connection failed'}
            
        try:
            cursor = conn.cursor(cursor_factory=DictCursor)
            yesterday = datetime.now() - timedelta(days=1)
            
            # Get login attempts
            cursor.execute('''
                SELECT COUNT(*), AVG(threat_level) 
                FROM login_attempts 
                WHERE timestamp > %s
            ''', (yesterday,))
            attempt_stats = cursor.fetchone()
            
            # Get security actions
            cursor.execute('''
                SELECT action_type, COUNT(*) 
                FROM security_actions 
                WHERE timestamp > %s 
                GROUP BY action_type
            ''', (yesterday,))
            actions = dict(cursor.fetchall())
            
            # Get honeypot interactions
            cursor.execute('''
                SELECT COUNT(*) 
                FROM honeypot_interactions 
                WHERE timestamp > %s
            ''', (yesterday,))
            honeypot_interactions = cursor.fetchone()[0]
            
            cursor.close()
            conn.close()
            
            report = {
                'date': datetime.now().strftime('%Y-%m-%d'),
                'total_login_attempts': attempt_stats[0] or 0,
                'average_threat_level': round(float(attempt_stats[1]) if attempt_stats[1] else 0, 2),
                'security_actions': actions,
                'honeypot_interactions': honeypot_interactions,
                'blacklisted_ips': list(self.blacklisted_ips),
                'whitelisted_ips': list(self.whitelisted_ips),
                'database': 'PostgreSQL',
                'status': 'Active'
            }
            
            return report
            
        except Exception as e:
            print(f"Error generating report: {e}")
            if conn:
                conn.close()
            return {'error': f'Report generation failed: {str(e)}'}
