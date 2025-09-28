import time
import re
import json
import random
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import requests
from bs4 import BeautifulSoup

# Common IDOR-vulnerable endpoints and patterns
IDOR_ENDPOINTS = [
    "/user/{id}",
    "/profile/{id}",
    "/account/{id}",
    "/admin/user/{id}",
    "/api/user/{id}",
    "/api/users/{id}",
    "/document/{id}",
    "/file/{id}",
    "/order/{id}",
    "/invoice/{id}",
    "/report/{id}",
    "/message/{id}",
    "/ticket/{id}",
    "/customer/{id}",
    "/employee/{id}",
    "/transaction/{id}"
]

# Common admin/privileged paths
ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/admin.php",
    "/admin/",
    "/admin/index.php",
    "/admin/login.php",
    "/admin/dashboard",
    "/admin/users",
    "/admin/config",
    "/admin/settings",
    "/management",
    "/manager",
    "/control",
    "/cp",
    "/admincp",
    "/moderator",
    "/staff",
    "/backend",
    "/console"
]

# HTTP methods to test
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Common ID patterns and formats
ID_PATTERNS = {
    'numeric': [1, 2, 3, 10, 100, 999, 1000, 9999, 12345],
    'sequential': [1, 2, 3, 4, 5],
    'guid': ["12345678-1234-1234-1234-123456789012", "00000000-0000-0000-0000-000000000000"],
    'base64': ["dXNlcjE=", "dXNlcjI=", "YWRtaW4="],  # user1, user2, admin encoded
    'hex': ["deadbeef", "12345678", "abcdef01"],
    'username': ["admin", "user", "test", "guest", "demo", "administrator"]
}

class AccessControlTester:
    """Access Control and IDOR Security Testing Module"""
    
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []
        self.discovered_endpoints = []
        self.baseline_responses = {}
        self.authenticated_session = None
        
    def discover_sensitive_endpoints(self, base_url, pages):
        """Discover potentially sensitive endpoints from crawled pages"""
        print("[*] Discovering sensitive endpoints and parameters")
        
        # Check for direct admin paths
        for admin_path in ADMIN_PATHS:
            test_url = urljoin(base_url, admin_path)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200:
                    self.discovered_endpoints.append({
                        'url': test_url,
                        'type': 'admin_path',
                        'status': response.status_code,
                        'length': len(response.text)
                    })
                    print(f"  [+] Found accessible admin endpoint: {test_url}")
                elif response.status_code == 403:
                    self.discovered_endpoints.append({
                        'url': test_url,
                        'type': 'admin_path_forbidden',
                        'status': response.status_code,
                        'length': len(response.text)
                    })
                    print(f"  [+] Found protected admin endpoint: {test_url} (403)")
            except:
                pass
        
        # Extract URLs with potential IDOR parameters
        for url, html in pages.items():
            self.extract_idor_candidates(url, html)
            
    def extract_idor_candidates(self, page_url, html):
        """Extract URLs that might be vulnerable to IDOR attacks"""
        soup = BeautifulSoup(html, 'html.parser')
        
        # Look for links with ID patterns
        for link in soup.find_all('a', href=True):
            href = urljoin(page_url, link['href'])
            parsed = urlparse(href)
            
            # Check for numeric IDs in path
            path_parts = parsed.path.split('/')
            for part in path_parts:
                if part.isdigit() and len(part) > 0:
                    self.discovered_endpoints.append({
                        'url': href,
                        'type': 'idor_candidate',
                        'id_value': part,
                        'id_type': 'numeric'
                    })
                    print(f"  [+] Found potential IDOR endpoint: {href}")
            
            # Check for ID parameters in query string
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name, param_values in params.items():
                    if any(id_keyword in param_name.lower() for id_keyword in ['id', 'user', 'account', 'profile', 'doc']):
                        for value in param_values:
                            if value.isdigit() or len(value) > 5:  # Likely an ID
                                self.discovered_endpoints.append({
                                    'url': href,
                                    'type': 'idor_param',
                                    'param_name': param_name,
                                    'id_value': value,
                                    'id_type': 'numeric' if value.isdigit() else 'string'
                                })
                                print(f"  [+] Found potential IDOR parameter: {param_name}={value} in {href}")
    
    def test_horizontal_privilege_escalation(self):
        """Test for horizontal privilege escalation (accessing other users' data)"""
        print("[*] Testing for horizontal privilege escalation")
        
        for endpoint in self.discovered_endpoints:
            if endpoint['type'] in ['idor_candidate', 'idor_param']:
                print(f"  [*] Testing IDOR at {endpoint['url']}")
                
                # Get baseline response
                try:
                    baseline_response = self.session.get(endpoint['url'], timeout=self.timeout)
                    self.baseline_responses[endpoint['url']] = {
                        'status': baseline_response.status_code,
                        'length': len(baseline_response.text),
                        'content': baseline_response.text[:500]  # First 500 chars for comparison
                    }
                    
                    if baseline_response.status_code == 200:
                        self.test_id_manipulation(endpoint, baseline_response)
                    
                except Exception as e:
                    print(f"[!] Error testing {endpoint['url']}: {e}")
                    
                time.sleep(0.2)  # Rate limiting
    
    def test_id_manipulation(self, endpoint, baseline_response):
        """Test different ID manipulation techniques"""
        original_id = endpoint.get('id_value', '1')
        id_type = endpoint.get('id_type', 'numeric')
        
        # Generate test IDs based on the original ID type
        test_ids = self.generate_test_ids(original_id, id_type)
        
        for test_id in test_ids:
            try:
                # Create modified URL
                if endpoint['type'] == 'idor_candidate':
                    modified_url = endpoint['url'].replace(str(original_id), str(test_id))
                elif endpoint['type'] == 'idor_param':
                    parsed = urlparse(endpoint['url'])
                    params = parse_qs(parsed.query)
                    params[endpoint['param_name']] = [str(test_id)]
                    new_query = urlencode(params, doseq=True)
                    modified_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                else:
                    continue
                
                # Test the modified URL
                response = self.session.get(modified_url, timeout=self.timeout)
                
                # Analyze response for IDOR vulnerability
                if self.analyze_idor_response(endpoint['url'], modified_url, baseline_response, response, test_id):
                    break  # Found vulnerability, no need to test more IDs for this endpoint
                
                time.sleep(0.1)  # Small delay between requests
                
            except Exception as e:
                print(f"[!] Error testing ID {test_id}: {e}")
    
    def generate_test_ids(self, original_id, id_type):
        """Generate test IDs for IDOR testing"""
        test_ids = []
        
        if id_type == 'numeric' and original_id.isdigit():
            original_num = int(original_id)
            # Test nearby numbers
            test_ids.extend([
                original_num - 1,
                original_num + 1,
                original_num - 10,
                original_num + 10,
                1,  # Common first user
                2,  # Common second user
                0,  # Edge case
                -1, # Negative number
                999999  # Large number
            ])
        else:
            # Test common patterns for string IDs
            test_ids.extend(ID_PATTERNS['username'])
            test_ids.extend(ID_PATTERNS['numeric'])
        
        return test_ids
    
    def analyze_idor_response(self, original_url, modified_url, baseline_response, test_response, test_id):
        """Analyze response to determine if IDOR vulnerability exists"""
        # Check if we got a successful response with different content
        if test_response.status_code == 200:
            baseline_length = len(baseline_response.text)
            test_length = len(test_response.text)
            
            # If response lengths are significantly different, might be different data
            length_diff = abs(baseline_length - test_length)
            if length_diff > 100:  # Significant difference
                # Further analyze content
                baseline_content = baseline_response.text.lower()
                test_content = test_response.text.lower()
                
                # Look for different user identifiers
                if self.contains_different_user_data(baseline_content, test_content):
                    finding = {
                        'type': 'horizontal_privilege_escalation',
                        'original_url': original_url,
                        'modified_url': modified_url,
                        'test_id': test_id,
                        'evidence': f'Response content differs significantly (baseline: {baseline_length} bytes, test: {test_length} bytes)',
                        'severity': 'High',
                        'fix_suggestion': 'Implement proper access controls to verify user ownership of resources'
                    }
                    self.findings.append(finding)
                    print(f"[!] Potential IDOR vulnerability found: {modified_url}")
                    return True
        
        # Check for error messages that reveal information
        elif test_response.status_code in [403, 401]:
            if baseline_response.status_code == 200:
                # This might be good - access is being denied
                pass
        elif test_response.status_code == 404:
            if baseline_response.status_code == 200:
                # Resource doesn't exist for this ID - might be normal
                pass
        
        return False
    
    def contains_different_user_data(self, baseline_content, test_content):
        """Check if responses contain different user-specific data"""
        # Look for different email patterns
        baseline_emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', baseline_content))
        test_emails = set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', test_content))
        
        if baseline_emails != test_emails and len(test_emails) > 0:
            return True
        
        # Look for different phone numbers
        baseline_phones = set(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', baseline_content))
        test_phones = set(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', test_content))
        
        if baseline_phones != test_phones and len(test_phones) > 0:
            return True
        
        # Look for different names (simple heuristic)
        baseline_names = set(re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', baseline_content))
        test_names = set(re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', test_content))
        
        if baseline_names != test_names and len(test_names) > 0:
            return True
        
        return False
    
    def test_vertical_privilege_escalation(self):
        """Test for vertical privilege escalation (accessing admin functions)"""
        print("[*] Testing for vertical privilege escalation")
        
        admin_endpoints = [ep for ep in self.discovered_endpoints if ep['type'] in ['admin_path', 'admin_path_forbidden']]
        
        for endpoint in admin_endpoints:
            print(f"  [*] Testing admin access at {endpoint['url']}")
            
            # Test different HTTP methods
            for method in HTTP_METHODS:
                try:
                    if method == 'GET':
                        response = self.session.get(endpoint['url'], timeout=self.timeout)
                    elif method == 'POST':
                        response = self.session.post(endpoint['url'], timeout=self.timeout)
                    elif method == 'PUT':
                        response = self.session.put(endpoint['url'], timeout=self.timeout)
                    elif method == 'DELETE':
                        response = self.session.delete(endpoint['url'], timeout=self.timeout)
                    elif method == 'PATCH':
                        response = self.session.patch(endpoint['url'], timeout=self.timeout)
                    elif method == 'HEAD':
                        response = self.session.head(endpoint['url'], timeout=self.timeout)
                    elif method == 'OPTIONS':
                        response = self.session.options(endpoint['url'], timeout=self.timeout)
                    
                    if response.status_code == 200 and 'admin' in response.text.lower():
                        finding = {
                            'type': 'vertical_privilege_escalation',
                            'url': endpoint['url'],
                            'method': method,
                            'evidence': f'Admin interface accessible via {method} method',
                            'severity': 'High',
                            'fix_suggestion': 'Implement proper authentication and authorization checks'
                        }
                        self.findings.append(finding)
                        print(f"[!] Admin interface accessible: {endpoint['url']} via {method}")
                    
                    time.sleep(0.1)
                    
                except Exception as e:
                    continue
    
    def test_path_traversal_access_control(self, base_url):
        """Test for path traversal in access control contexts"""
        print("[*] Testing path traversal for access control bypass")
        
        path_traversal_payloads = [
            "../admin",
            "../../admin", 
            "../../../admin",
            "..%2fadmin",
            "..%252fadmin",
            "%2e%2e%2fadmin",
            "%2e%2e/%2e%2e/admin",
            "....//admin",
            "..;/admin"
        ]
        
        for payload in path_traversal_payloads:
            test_url = urljoin(base_url, payload)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200 and any(keyword in response.text.lower() for keyword in ['admin', 'dashboard', 'control panel']):
                    finding = {
                        'type': 'path_traversal_access_control',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'Path traversal allowed access to admin interface',
                        'severity': 'High',
                        'fix_suggestion': 'Implement proper input validation and access control checks'
                    }
                    self.findings.append(finding)
                    print(f"[!] Path traversal access control bypass: {test_url}")
                
                time.sleep(0.1)
                
            except Exception as e:
                continue
    
    def test_forced_browsing(self, base_url):
        """Test for forced browsing vulnerabilities"""
        print("[*] Testing forced browsing")
        
        sensitive_files = [
            "/backup.sql",
            "/config.php",
            "/config.xml", 
            "/.env",
            "/database.sql",
            "/admin.php",
            "/test.php",
            "/phpinfo.php",
            "/info.php",
            "/backup/",
            "/old/",
            "/temp/",
            "/tmp/",
            "/.git/",
            "/.svn/",
            "/web.config",
            "/htaccess.txt",
            "/.htaccess"
        ]
        
        for file_path in sensitive_files:
            test_url = urljoin(base_url, file_path)
            try:
                response = self.session.get(test_url, timeout=self.timeout)
                if response.status_code == 200 and len(response.text) > 100:  # Non-empty response
                    # Check for sensitive content indicators
                    content_lower = response.text.lower()
                    sensitive_indicators = ['password', 'database', 'config', 'admin', 'secret', 'key', 'token']
                    
                    if any(indicator in content_lower for indicator in sensitive_indicators):
                        finding = {
                            'type': 'forced_browsing',
                            'url': test_url,
                            'evidence': 'Sensitive file accessible via direct request',
                            'severity': 'Medium',
                            'fix_suggestion': 'Restrict access to sensitive files and directories'
                        }
                        self.findings.append(finding)
                        print(f"[!] Sensitive file accessible: {test_url}")
                
                time.sleep(0.1)
                
            except Exception as e:
                continue
    
    def test_missing_function_level_access_control(self, forms_by_url):
        """Test for missing function-level access control"""
        print("[*] Testing missing function-level access control")
        
        for url, forms in forms_by_url.items():
            for form in forms:
                action_url = form.get('action', url)
                
                # Look for admin-like functions
                admin_indicators = ['delete', 'remove', 'admin', 'manage', 'edit', 'update', 'create']
                form_text = str(form).lower()
                
                if any(indicator in form_text or indicator in action_url.lower() for indicator in admin_indicators):
                    print(f"  [*] Testing admin function at {action_url}")
                    
                    # Try to access the function without proper authentication
                    form_data = {}
                    for input_field in form.get('inputs', []):
                        input_name = input_field.get('name')
                        if input_name:
                            form_data[input_name] = input_field.get('value', 'test')
                    
                    try:
                        if form.get('method', 'get').lower() == 'post':
                            response = self.session.post(action_url, data=form_data, timeout=self.timeout)
                        else:
                            response = self.session.get(action_url, params=form_data, timeout=self.timeout)
                        
                        # Check if function was executed without proper authorization
                        if response.status_code == 200:
                            success_indicators = ['success', 'deleted', 'updated', 'created', 'saved']
                            response_text = response.text.lower()
                            
                            if any(indicator in response_text for indicator in success_indicators):
                                finding = {
                                    'type': 'missing_function_level_access_control',
                                    'url': action_url,
                                    'evidence': 'Administrative function accessible without proper authorization',
                                    'severity': 'High', 
                                    'fix_suggestion': 'Implement proper authorization checks for all administrative functions'
                                }
                                self.findings.append(finding)
                                print(f"[!] Admin function accessible without authorization: {action_url}")
                        
                        time.sleep(0.2)
                        
                    except Exception as e:
                        continue
    
    def run(self, pages, forms_by_url, base_url):
        """Run all access control tests"""
        print("[*] Starting access control and IDOR tests")
        
        # Discover sensitive endpoints
        self.discover_sensitive_endpoints(base_url, pages)
        
        # Test horizontal privilege escalation (IDOR)
        self.test_horizontal_privilege_escalation()
        
        # Test vertical privilege escalation
        self.test_vertical_privilege_escalation()
        
        # Test path traversal for access control bypass
        self.test_path_traversal_access_control(base_url)
        
        # Test forced browsing
        self.test_forced_browsing(base_url)
        
        # Test missing function-level access control
        self.test_missing_function_level_access_control(forms_by_url)
        
        return self.findings
    
    def generate_report(self):
        """Generate comprehensive access control vulnerability report"""
        if not self.findings:
            print("\n[*] No access control vulnerabilities found.")
            return
        
        print("\n" + "="*80)
        print("ACCESS CONTROL & IDOR VULNERABILITY REPORT")
        print("="*80)
        
        # Group findings by severity and type
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
                    
                    if 'original_url' in finding:
                        print(f"   Original URL: {finding['original_url']}")
                        print(f"   Modified URL: {finding['modified_url']}")
                        print(f"   Test ID: {finding['test_id']}")
                    
                    if 'method' in finding:
                        print(f"   HTTP Method: {finding['method']}")
                    
                    if 'payload' in finding:
                        print(f"   Payload: {finding['payload']}")
                    
                    print(f"   Evidence: {finding['evidence']}")
                    print(f"   Fix: {finding['fix_suggestion']}")
        
        print(f"\nTotal access control vulnerabilities found: {len(self.findings)}")
        
        # Access control recommendations
        print("\n--- Access Control Security Recommendations ---")
        recommendations = [
            "Implement proper authentication and authorization checks for all resources",
            "Use indirect object references (maps/hashes) instead of direct database IDs",
            "Validate user permissions for every resource access attempt",
            "Implement role-based access control (RBAC) consistently",
            "Use allowlist-based access control rather than blocklist",
            "Log and monitor access control violations",
            "Regularly audit user permissions and remove unnecessary access",
            "Implement proper session management and timeout controls",
            "Use principle of least privilege for all user accounts",
            "Secure administrative interfaces with additional authentication factors"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i:2}. {rec}")
        
        print("="*80)