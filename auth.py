import time
import re
import json
import base64
import hashlib
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import requests
from bs4 import BeautifulSoup

# Common weak credentials for testing
WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("administrator", "admin"),
    ("root", "root"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("demo", "demo"),
    ("admin", ""),
    ("", "admin"),
]

# Common authentication endpoints
AUTH_ENDPOINTS = [
    "/login",
    "/signin",
    "/auth",
    "/authentication",
    "/admin/login",
    "/user/login",
    "/account/login",
    "/wp-login.php",
    "/admin.php",
    "/login.php",
    "/signin.php",
    "/auth/login",
    "/api/auth",
    "/api/login",
    "/oauth/token",
    "/sso/login"
]

# Password reset endpoints
RESET_ENDPOINTS = [
    "/reset",
    "/forgot",
    "/password-reset",
    "/reset-password",
    "/forgot-password",
    "/recover",
    "/recovery",
    "/api/reset",
    "/api/forgot",
    "/auth/reset"
]

# JWT algorithms that should be rejected
WEAK_JWT_ALGS = ["none", "HS256", "RS256"]

class AuthTester:
    """Authentication and Session Management Security Tester"""
    
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []
        self.auth_endpoints = []
        self.reset_endpoints = []
        self.discovered_forms = {}
        self.session_tokens = {}
        
    def discover_auth_endpoints(self, base_url, pages):
        """Discover authentication-related endpoints from crawled pages"""
        print("[*] Discovering authentication endpoints")
        
        # Check common endpoints
        for endpoint in AUTH_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    self.auth_endpoints.append(test_url)
                    print(f"  [+] Found auth endpoint: {test_url}")
            except:
                pass
        
        # Check for reset endpoints
        for endpoint in RESET_ENDPOINTS:
            test_url = urljoin(base_url, endpoint)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    self.reset_endpoints.append(test_url)
                    print(f"  [+] Found reset endpoint: {test_url}")
            except:
                pass
        
        # Extract login forms from crawled pages
        for url, html in pages.items():
            forms = self.extract_auth_forms(html, url)
            if forms:
                self.discovered_forms[url] = forms
                print(f"  [+] Found {len(forms)} auth form(s) at: {url}")
    
    def extract_auth_forms(self, html, page_url):
        """Extract authentication forms from HTML"""
        auth_forms = []
        soup = BeautifulSoup(html, 'html.parser')
        
        for form in soup.find_all('form'):
            # Look for common auth form indicators
            form_text = str(form).lower()
            auth_indicators = ['password', 'login', 'signin', 'username', 'email', 'auth']
            
            if any(indicator in form_text for indicator in auth_indicators):
                form_info = {
                    'method': form.get('method', 'get').lower(),
                    'action': urljoin(page_url, form.get('action', '')),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_info = {
                        'name': input_tag.get('name'),
                        'type': input_tag.get('type', 'text').lower(),
                        'value': input_tag.get('value', '')
                    }
                    form_info['inputs'].append(input_info)
                
                auth_forms.append(form_info)
        
        return auth_forms
    
    def test_weak_credentials(self):
        """Test for weak or default credentials"""
        print("[*] Testing for weak/default credentials")
        
        for url, forms in self.discovered_forms.items():
            for form in forms:
                for username, password in WEAK_CREDENTIALS:
                    self.attempt_login(form, username, password, "weak_credentials")
                    time.sleep(0.2)  # Rate limiting
    
    def attempt_login(self, form, username, password, test_type):
        """Attempt to log in with given credentials"""
        form_data = {}
        username_field = None
        password_field = None
        
        # Identify username and password fields
        for input_field in form['inputs']:
            input_name = input_field['name']
            input_type = input_field['type']
            
            if not input_name:
                continue
                
            if input_type == 'password':
                password_field = input_name
                form_data[input_name] = password
            elif input_type in ['text', 'email'] or 'user' in input_name.lower() or 'email' in input_name.lower():
                if not username_field:  # Use the first username-like field
                    username_field = input_name
                    form_data[input_name] = username
            else:
                form_data[input_name] = input_field.get('value', '')
        
        if not username_field or not password_field:
            return False
        
        try:
            if form['method'] == 'get':
                response = self.session.get(form['action'], params=form_data, timeout=self.timeout)
            else:
                response = self.session.post(form['action'], data=form_data, timeout=self.timeout)
            
            # Check for successful login indicators
            if self.check_login_success(response, username, password):
                finding = {
                    'type': test_type,
                    'url': form['action'],
                    'username': username,
                    'password': password,
                    'evidence': 'Successful login with weak credentials',
                    'severity': 'High',
                    'fix_suggestion': 'Enforce strong password policies and disable default accounts'
                }
                self.findings.append(finding)
                print(f"[!] Successful login found: {username}:{password} at {form['action']}")
                
                # Store session tokens for further testing
                self.capture_session_tokens(response)
                return True
        
        except Exception as e:
            print(f"[!] Error testing credentials {username}:{password}: {e}")
        
        return False
    
    def check_login_success(self, response, username, password):
        """Check if login was successful based on response"""
        # Check status code
        if response.status_code in [200, 302, 301]:
            response_text = response.text.lower()
            
            # Positive indicators of successful login
            success_indicators = [
                'welcome', 'dashboard', 'profile', 'logout', 'signed in',
                'logged in', 'authentication successful', 'login successful'
            ]
            
            # Negative indicators of failed login
            fail_indicators = [
                'invalid', 'incorrect', 'wrong', 'failed', 'error',
                'denied', 'unauthorized', 'authentication failed'
            ]
            
            has_success = any(indicator in response_text for indicator in success_indicators)
            has_failure = any(indicator in response_text for indicator in fail_indicators)
            
            # Check for redirect to dashboard/profile pages
            if response.status_code in [302, 301]:
                location = response.headers.get('Location', '').lower()
                if any(page in location for page in ['dashboard', 'profile', 'home', 'admin']):
                    return True
            
            # Check for new cookies (session tokens)
            if response.cookies and not has_failure:
                return True
            
            return has_success and not has_failure
        
        return False
    
    def capture_session_tokens(self, response):
        """Capture session tokens from response"""
        for cookie in response.cookies:
            if any(token_name in cookie.name.lower() for token_name in ['session', 'token', 'auth', 'jwt']):
                self.session_tokens[cookie.name] = {
                    'value': cookie.value,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                    'samesite': cookie.get_nonstandard_attr('SameSite'),
                    'expires': cookie.expires
                }
        
        # Check for Authorization header or Bearer tokens
        auth_header = response.request.headers.get('Authorization')
        if auth_header:
            self.session_tokens['Authorization'] = {'value': auth_header}
    
    def test_brute_force_protection(self):
        """Test for brute force protection mechanisms"""
        print("[*] Testing brute force protection")
        
        for url, forms in self.discovered_forms.items():
            for form in forms:
                print(f"  [*] Testing brute force protection at {form['action']}")
                
                # Attempt multiple failed logins
                failed_attempts = 0
                for i in range(10):  # Try 10 failed attempts
                    fake_username = f"testuser{i}"
                    fake_password = f"wrongpass{i}"
                    
                    success = self.attempt_login(form, fake_username, fake_password, "brute_force_test")
                    if not success:
                        failed_attempts += 1
                    
                    time.sleep(0.1)  # Small delay
                
                # If all 10 attempts were allowed without blocking, it's a vulnerability
                if failed_attempts >= 8:  # Allow some margin for false positives
                    finding = {
                        'type': 'brute_force_vulnerability',
                        'url': form['action'],
                        'evidence': f'{failed_attempts} failed login attempts were allowed without blocking',
                        'severity': 'Medium',
                        'fix_suggestion': 'Implement account lockout, rate limiting, or CAPTCHA after failed attempts'
                    }
                    self.findings.append(finding)
                    print(f"[!] No brute force protection found at {form['action']}")
    
    def test_password_reset_flows(self):
        """Test password reset functionality for vulnerabilities"""
        print("[*] Testing password reset flows")
        
        for reset_url in self.reset_endpoints:
            print(f"  [*] Testing password reset at {reset_url}")
            
            try:
                # Get reset form
                response = self.session.get(reset_url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for form in soup.find_all('form'):
                    form_data = {}
                    email_field = None
                    
                    for input_tag in form.find_all('input'):
                        input_name = input_tag.get('name')
                        input_type = input_tag.get('type', 'text')
                        
                        if input_type == 'email' or 'email' in input_name.lower():
                            email_field = input_name
                        
                        form_data[input_name] = input_tag.get('value', '')
                    
                    if email_field:
                        # Test with valid and invalid emails
                        test_emails = ['test@example.com', 'nonexistent@example.com']
                        responses = {}
                        
                        for email in test_emails:
                            form_data[email_field] = email
                            action_url = urljoin(reset_url, form.get('action', ''))
                            
                            if form.get('method', 'get').lower() == 'post':
                                reset_response = self.session.post(action_url, data=form_data, timeout=self.timeout)
                            else:
                                reset_response = self.session.get(action_url, params=form_data, timeout=self.timeout)
                            
                            responses[email] = {
                                'status_code': reset_response.status_code,
                                'content': reset_response.text,
                                'length': len(reset_response.text)
                            }
                            time.sleep(0.5)
                        
                        # Check for user enumeration
                        if self.check_user_enumeration(responses):
                            finding = {
                                'type': 'user_enumeration',
                                'url': reset_url,
                                'evidence': 'Different responses for valid vs invalid email addresses',
                                'severity': 'Medium',
                                'fix_suggestion': 'Return identical responses for valid and invalid email addresses'
                            }
                            self.findings.append(finding)
                            print(f"[!] User enumeration vulnerability found in password reset")
            
            except Exception as e:
                print(f"[!] Error testing password reset at {reset_url}: {e}")
    
    def check_user_enumeration(self, responses):
        """Check if responses reveal user enumeration"""
        if len(responses) < 2:
            return False
        
        response_list = list(responses.values())
        
        # Check for significant differences in response length
        lengths = [r['length'] for r in response_list]
        if max(lengths) - min(lengths) > 50:  # Significant difference
            return True
        
        # Check for different status codes
        status_codes = [r['status_code'] for r in response_list]
        if len(set(status_codes)) > 1:
            return True
        
        # Check for different error messages
        contents = [r['content'].lower() for r in response_list]
        if any('not found' in content or 'does not exist' in content for content in contents):
            if not all('not found' in content or 'does not exist' in content for content in contents):
                return True
        
        return False
    
    def test_session_security(self):
        """Test session token security"""
        print("[*] Testing session security")
        
        for token_name, token_info in self.session_tokens.items():
            print(f"  [*] Analyzing token: {token_name}")
            
            # Check cookie security flags
            if 'secure' in token_info:
                if not token_info['secure']:
                    finding = {
                        'type': 'insecure_cookie',
                        'token': token_name,
                        'evidence': 'Session cookie missing Secure flag',
                        'severity': 'Medium',
                        'fix_suggestion': 'Set Secure flag on all authentication cookies'
                    }
                    self.findings.append(finding)
                    print(f"[!] Cookie {token_name} missing Secure flag")
                
                if not token_info.get('httponly', False):
                    finding = {
                        'type': 'insecure_cookie',
                        'token': token_name,
                        'evidence': 'Session cookie missing HttpOnly flag',
                        'severity': 'Medium',
                        'fix_suggestion': 'Set HttpOnly flag on all authentication cookies'
                    }
                    self.findings.append(finding)
                    print(f"[!] Cookie {token_name} missing HttpOnly flag")
                
                if not token_info.get('samesite'):
                    finding = {
                        'type': 'insecure_cookie',
                        'token': token_name,
                        'evidence': 'Session cookie missing SameSite attribute',
                        'severity': 'Low',
                        'fix_suggestion': 'Set SameSite attribute on authentication cookies'
                    }
                    self.findings.append(finding)
                    print(f"[!] Cookie {token_name} missing SameSite attribute")
            
            # Analyze JWT tokens
            if self.is_jwt_token(token_info['value']):
                self.analyze_jwt_token(token_name, token_info['value'])
    
    def is_jwt_token(self, token_value):
        """Check if a token is a JWT"""
        return len(token_value.split('.')) == 3
    
    def analyze_jwt_token(self, token_name, token_value):
        """Analyze JWT token for security issues"""
        print(f"  [*] Analyzing JWT token: {token_name}")
        
        try:
            # Decode JWT header and payload (without verification)
            parts = token_value.split('.')
            if len(parts) != 3:
                return
            
            # Decode header
            header_data = base64.urlsafe_b64decode(parts[0] + '==')
            header = json.loads(header_data)
            
            # Decode payload
            payload_data = base64.urlsafe_b64decode(parts[1] + '==')
            payload = json.loads(payload_data)
            
            # Check algorithm
            alg = header.get('alg', '').lower()
            if alg == 'none':
                finding = {
                    'type': 'jwt_no_algorithm',
                    'token': token_name,
                    'evidence': 'JWT uses "none" algorithm - no signature verification',
                    'severity': 'High',
                    'fix_suggestion': 'Use proper JWT signing algorithms (HS256, RS256, etc.)'
                }
                self.findings.append(finding)
                print(f"[!] JWT {token_name} uses 'none' algorithm")
            
            # Check for expiration
            if 'exp' not in payload:
                finding = {
                    'type': 'jwt_no_expiration',
                    'token': token_name,
                    'evidence': 'JWT missing expiration claim (exp)',
                    'severity': 'Medium',
                    'fix_suggestion': 'Include expiration claim (exp) in JWT tokens'
                }
                self.findings.append(finding)
                print(f"[!] JWT {token_name} missing expiration")
            
            # Check for issuer
            if 'iss' not in payload:
                finding = {
                    'type': 'jwt_no_issuer',
                    'token': token_name,
                    'evidence': 'JWT missing issuer claim (iss)',
                    'severity': 'Low',
                    'fix_suggestion': 'Include issuer claim (iss) in JWT tokens'
                }
                self.findings.append(finding)
            
            # Check for sensitive data in payload
            sensitive_fields = ['password', 'ssn', 'credit_card', 'api_key', 'secret']
            for field in payload:
                if any(sensitive in field.lower() for sensitive in sensitive_fields):
                    finding = {
                        'type': 'jwt_sensitive_data',
                        'token': token_name,
                        'evidence': f'JWT contains potentially sensitive field: {field}',
                        'severity': 'Medium',
                        'fix_suggestion': 'Avoid storing sensitive data in JWT payload'
                    }
                    self.findings.append(finding)
                    print(f"[!] JWT {token_name} contains sensitive field: {field}")
        
        except Exception as e:
            print(f"[!] Error analyzing JWT {token_name}: {e}")
    
    def test_csrf_protection(self, pages, forms_by_url):
        """Test for CSRF protection on authentication forms"""
        print("[*] Testing CSRF protection")
        
        for url, forms in forms_by_url.items():
            for form in forms:
                if form['method'].lower() == 'post':
                    # Check for CSRF token in form
                    has_csrf_token = False
                    for input_field in form['inputs']:
                        input_name = input_field.get('name', '').lower()
                        if any(token_name in input_name for token_name in ['csrf', 'token', '_token', 'authenticity']):
                            has_csrf_token = True
                            break
                    
                    if not has_csrf_token:
                        finding = {
                            'type': 'missing_csrf_protection',
                            'url': url,
                            'form_action': form['action'],
                            'evidence': 'POST form missing CSRF token',
                            'severity': 'Medium',
                            'fix_suggestion': 'Implement CSRF tokens for all state-changing forms'
                        }
                        self.findings.append(finding)
                        print(f"[!] Missing CSRF protection on form at {form['action']}")
    
    def test_logout_functionality(self):
        """Test logout functionality and session invalidation"""
        print("[*] Testing logout functionality")
        
        # Look for logout endpoints
        logout_endpoints = []
        for endpoint in ['/logout', '/signout', '/exit', '/auth/logout', '/api/logout']:
            test_url = urljoin(self.session.cookies.get_dict().get('base_url', 'http://localhost'), endpoint)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    logout_endpoints.append(test_url)
            except:
                pass
        
        for logout_url in logout_endpoints:
            print(f"  [*] Testing logout at {logout_url}")
            
            # Store current session tokens
            original_tokens = dict(self.session.cookies)
            
            try:
                # Perform logout
                response = self.session.post(logout_url, timeout=self.timeout)
                
                # Check if tokens were invalidated
                current_tokens = dict(self.session.cookies)
                
                tokens_changed = original_tokens != current_tokens
                
                if not tokens_changed:
                    finding = {
                        'type': 'incomplete_logout',
                        'url': logout_url,
                        'evidence': 'Session tokens not invalidated after logout',
                        'severity': 'Medium',
                        'fix_suggestion': 'Invalidate all session tokens server-side on logout'
                    }
                    self.findings.append(finding)
                    print(f"[!] Incomplete logout - tokens not invalidated")
            
            except Exception as e:
                print(f"[!] Error testing logout at {logout_url}: {e}")
    
    def run(self, pages, forms_by_url, base_url):
        """Run all authentication tests"""
        print("[*] Starting authentication security tests")
        
        # Discover authentication endpoints
        self.discover_auth_endpoints(base_url, pages)
        
        # Test weak credentials
        if self.discovered_forms:
            self.test_weak_credentials()
            
            # Test brute force protection
            self.test_brute_force_protection()
        
        # Test password reset flows
        if self.reset_endpoints:
            self.test_password_reset_flows()
        
        # Test session security
        if self.session_tokens:
            self.test_session_security()
        
        # Test CSRF protection
        self.test_csrf_protection(pages, forms_by_url)
        
        # Test logout functionality
        self.test_logout_functionality()
        
        return self.findings
    
    def generate_report(self):
        """Generate a comprehensive authentication security report"""
        if not self.findings:
            print("\n[*] No authentication vulnerabilities found.")
            return
        
        print("\n" + "="*80)
        print("AUTHENTICATION SECURITY VULNERABILITY REPORT")
        print("="*80)
        
        # Group findings by severity
        severity_order = ['High', 'Medium', 'Low']
        findings_by_severity = {severity: [] for severity in severity_order}
        
        for finding in self.findings:
            severity = finding.get('severity', 'Medium')
            findings_by_severity[severity].append(finding)
        
        # Print findings by severity
        for severity in severity_order:
            if findings_by_severity[severity]:
                print(f"\n--- {severity} Severity Issues ---")
                for i, finding in enumerate(findings_by_severity[severity], 1):
                    print(f"\n{i}. {finding['type'].replace('_', ' ').title()}")
                    print(f"   URL: {finding.get('url', 'N/A')}")
                    
                    if 'username' in finding:
                        print(f"   Credentials: {finding['username']}:{finding['password']}")
                    if 'token' in finding:
                        print(f"   Token: {finding['token']}")
                    if 'form_action' in finding:
                        print(f"   Form Action: {finding['form_action']}")
                    
                    print(f"   Evidence: {finding['evidence']}")
                    print(f"   Fix: {finding['fix_suggestion']}")
        
        print(f"\nTotal authentication vulnerabilities found: {len(self.findings)}")
        
        # Security recommendations summary
        print("\n--- Security Recommendations Summary ---")
        recommendations = [
            "Enforce strong password policies and disable default accounts",
            "Implement rate limiting and account lockout mechanisms",
            "Set proper security flags on authentication cookies (Secure, HttpOnly, SameSite)",
            "Implement CSRF protection for all state-changing operations",
            "Use proper JWT signing algorithms and include expiration claims",
            "Ensure complete session invalidation on logout",
            "Return identical responses for password reset regardless of email validity",
            "Enable HTTPS everywhere and use HSTS headers",
            "Implement MFA for privileged accounts",
            "Log and monitor authentication events for anomalies"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i:2}. {rec}")
        
        print("="*80)