import time
import re
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin
import requests

# Enhanced XSS payloads for different types of attacks
XSS_PAYLOADS = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
    ],
    "dom_based": [
        "#<script>alert('DOM XSS')</script>",
        "#javascript:alert('DOM XSS')",
        "#\" onload=\"alert('DOM XSS')",
        "javascript:alert('DOM XSS')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnRE9NIFhTUycpPC9zY3JpcHQ+",
    ],
    "stored": [
        "<script>alert('Stored XSS')</script>",
        "<img src=x onerror=alert('Stored XSS')>",
        "<iframe src=\"javascript:alert('Stored XSS')\">",
        "<body onload=alert('Stored XSS')>",
    ],
    "obfuscated": [
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=x oneonerrorrror=alert('XSS')>",
        "<script>alert`XSS`</script>",
        "<img src=x onerror=alert&lpar;'XSS'&rpar;>",
    ],
    "svg": [
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
        "<svg><script>alert('XSS')</script></svg>",
    ]
}

# XSS detection patterns with DOM-specific indicators
XSS_INDICATORS = [
    "script", "onerror", "onload", "onfocus", "javascript:", "alert(",
    "svg", "iframe", "img", "body", "input", "textarea", "eval(",
    "document.write", "innerHTML", "setTimeout", "setInterval",
    "location.hash", "window.name", "document.cookie"
]

# Common API endpoints that might be vulnerable to stored XSS
COMMON_API_ENDPOINTS = [
    "/api/feedback",
    "/api/comments",
    "/api/reviews",
    "/api/users",
    "/api/products",
    "/api/contact",
    "/api/support",
    "/api/messages"
]

class XSSTester:
    """Enhanced XSS testing class with DOM-based and stored XSS capabilities."""
    def __init__(self, session=None, timeout=10):
        self.session = session or requests.Session()
        self.timeout = timeout
        self.findings = []
        self.stored_payloads = {}  # Track payloads for stored XSS verification
    
    def detect_xss_reflection(self, response_text, payload, url):
        """Detect if XSS payload is reflected in the response, including DOM indicators."""
        # Check if payload is directly reflected
        if payload in response_text:
            return True, "Payload directly reflected in response"
        
        # Check for common XSS indicators in the response
        response_lower = response_text.lower()
        for indicator in XSS_INDICATORS:
            if indicator in response_lower and any(char in response_lower for char in ["<", ">", "'", "\""]):
                return True, f"XSS indicator '{indicator}' found in response"
        
        # Check for encoded payload reflection
        encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace("\"", "&quot;")
        if encoded_payload in response_text:
            return True, "Payload reflected with encoding (possible filter bypass needed)"
        
        # Check for DOM-based XSS indicators in script tags
        if self.check_dom_xss_indicators(response_text, payload):
            return True, "DOM-based XSS indicators found in JavaScript code"
        
        # Check if payload appears in URL fragments (common for DOM XSS)
        if "#" in url and any(xss_indicator in url for xss_indicator in ["<", ">", "javascript:", "onload", "onerror"]):
            return True, "DOM XSS indicators found in URL fragment"
        
        return False, None
    
    def check_dom_xss_indicators(self, response_text, payload):
        """Check for DOM-based XSS indicators in JavaScript code."""
        # Look for JavaScript code that might handle user input dangerously
        script_patterns = [
            r"document\.write\([^)]*\)",
            r"innerHTML\s*=",
            r"eval\([^)]*\)",
            r"setTimeout\([^)]*\)",
            r"setInterval\([^)]*\)",
            r"location\.hash",
            r"window\.name",
            r"document\.cookie"
        ]
        
        for pattern in script_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def generate_xss_fix_suggestions(self, vulnerability_type, context="generic"):
        """Generate specific fix suggestions for XSS vulnerabilities."""
        base_suggestions = {
            'URL parameter': "Validate and sanitize all URL parameters",
            'Form field': "Implement input validation and output encoding for form fields",
            'DOM-based': "Sanitize user input used in DOM manipulation, avoid dangerous functions like innerHTML",
            'Stored': "Implement server-side validation and sanitization for all user-generated content"
        }
        
        context_specific = {
            'generic': [
                "Use context-specific output encoding (HTML, JavaScript, CSS, URL)",
                "Implement Content Security Policy (CSP) headers",
                "Use frameworks that automatically handle encoding (e.g., React, Angular)",
                "Validate input against a whitelist of allowed characters",
                "Use libraries like DOMPurify to sanitize HTML content"
            ],
            'DOM-based': [
                "Avoid using innerHTML, document.write(), and other dangerous DOM manipulation methods with user input",
                "Use textContent instead of innerHTML when possible",
                "Sanitize data from location.hash, window.name, and other DOM properties",
                "Use safe DOM manipulation methods like createElement, appendChild"
            ],
            'Stored': [
                "Implement server-side validation for all user-generated content",
                "Use parameterized queries to prevent SQL injection that could lead to stored XSS",
                "Regularly audit and sanitize stored data",
                "Implement proper output encoding when displaying user-generated content"
            ]
        }
        
        base = base_suggestions.get(vulnerability_type, "Implement input validation and output encoding")
        specifics = ". ".join(context_specific.get(context, context_specific['generic']))
        
        return f"{base}. {specifics}."
    
    def test_url_params_for_xss(self, url):
        """Test URL parameters for XSS vulnerabilities, including DOM-based."""
        print(f"[*] Testing URL parameters for XSS: {url}")
        
        # Parse URL into components 
        parsed = urlparse(url)
        
        # Extract and parse query string 
        query_dict = parse_qs(parsed.query)
        
        # Also test URL fragments for DOM-based XSS
        fragment = parsed.fragment
        
        # Test regular query parameters
        if query_dict:
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
                    for payload_type, payloads in XSS_PAYLOADS.items():
                        for payload in payloads:
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
                                
                                # Check for XSS reflection in response
                                found, evidence = self.detect_xss_reflection(response.text, payload, test_url)
                                
                                if found:
                                    context = "DOM-based" if payload_type == "dom_based" else "generic"
                                    fix_suggestion = self.generate_xss_fix_suggestions('URL parameter', context)
                                    
                                    finding = {
                                        'type': 'URL parameter',
                                        'url': test_url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'payload_type': payload_type,
                                        'evidence': evidence,
                                        'fix_suggestion': fix_suggestion,
                                        'response_snippet': response.text[:200] + "..." if len(response.text) > 200 else response.text
                                    }
                                    self.findings.append(finding)
                                    print(f"[!] Potential XSS vulnerability found in parameter '{param_name}'")
                                    print(f"    URL: {test_url}")
                                    print(f"    Evidence: {evidence}")
                            
                            except Exception as e:
                                print(f"[!] Error testing URL {test_url}: {e}")
                            
                            # Small delay between requests 
                            time.sleep(0.1)
        
        # Test URL fragments for DOM-based XSS
        if fragment:
            for payload_type, payloads in XSS_PAYLOADS.items():
                for payload in payloads:
                    if payload_type in ["dom_based", "basic"]:
                        # Create URL with XSS payload in fragment
                        test_url = urlunparse((
                            parsed.scheme,
                            parsed.netloc,
                            parsed.path,
                            parsed.params,
                            parsed.query,
                            payload
                        ))
                        
                        try:
                            # Send the request
                            response = self.session.get(test_url, timeout=self.timeout)
                            
                            # For DOM-based XSS, we need to check if the payload might be executed
                            # This is a heuristic approach since we can't execute JavaScript
                            if any(indicator in test_url for indicator in ["<", ">", "javascript:", "onload", "onerror"]):
                                evidence = "DOM XSS indicators found in URL fragment"
                                fix_suggestion = self.generate_xss_fix_suggestions('URL parameter', 'DOM-based')
                                
                                finding = {
                                    'type': 'URL fragment',
                                    'url': test_url,
                                    'parameter': 'fragment',
                                    'payload': payload,
                                    'payload_type': payload_type,
                                    'evidence': evidence,
                                    'fix_suggestion': fix_suggestion,
                                    'response_snippet': response.text[:200] + "..." if len(response.text) > 200 else response.text
                                }
                                self.findings.append(finding)
                                print(f"[!] Potential DOM-based XSS vulnerability found in URL fragment")
                                print(f"    URL: {test_url}")
                                print(f"    Evidence: {evidence}")
                        
                        except Exception as e:
                            print(f"[!] Error testing URL {test_url}: {e}")
                        
                        # Small delay between requests 
                        time.sleep(0.1)
    
    def test_forms_for_xss(self, forms_by_url):
        """Test HTML forms for XSS vulnerabilities, including stored XSS."""
        for url, forms in forms_by_url.items():
            for form in forms:
                print(f"[*] Testing form for XSS at {url}")
                
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
                
                # Test each form field with different payload types
                for input_field in form['inputs']:
                    input_name = input_field['name']
                    if not input_name:
                        continue
                    
                    for payload_type, payloads in XSS_PAYLOADS.items():
                        for payload in payloads:
                            # Create test data with payload in one field
                            test_data = form_data.copy()
                            test_data[input_name] = payload
                            
                            try:
                                # Submit the form
                                if method == 'get':
                                    response = self.session.get(action_url, params=test_data, timeout=self.timeout)
                                else:
                                    response = self.session.post(action_url, data=test_data, timeout=self.timeout)
                                
                                # Check for XSS reflection in response
                                found, evidence = self.detect_xss_reflection(response.text, payload, action_url)
                                
                                if found:
                                    context = "Stored" if payload_type == "stored" else "generic"
                                    fix_suggestion = self.generate_xss_fix_suggestions('Form field', context)
                                    
                                    finding = {
                                        'type': 'Form field',
                                        'url': url,
                                        'action': action_url,
                                        'field': input_name,
                                        'payload': payload,
                                        'payload_type': payload_type,
                                        'evidence': evidence,
                                        'fix_suggestion': fix_suggestion,
                                        'response_snippet': response.text[:200] + "..." if len(response.text) > 200 else response.text
                                    }
                                    self.findings.append(finding)
                                    print(f"[!] Potential XSS vulnerability found in form field '{input_name}'")
                                    print(f"    Form action: {action_url}")
                                    print(f"    Evidence: {evidence}")
                                    
                                    # If this might be a stored XSS, remember the payload for verification
                                    if payload_type == "stored":
                                        self.stored_payloads[payload] = {
                                            'url': url,
                                            'action': action_url,
                                            'field': input_name
                                        }
                            
                            except Exception as e:
                                print(f"[!] Error testing form field {input_name}: {e}")
                            
                            # Small delay between requests 
                            time.sleep(0.1)
    
    def test_api_endpoints_for_stored_xss(self, base_url):
        """Test common API endpoints for stored XSS vulnerabilities."""
        print("[*] Testing API endpoints for stored XSS")
        
        for endpoint in COMMON_API_ENDPOINTS:
            api_url = urljoin(base_url, endpoint)
            
            # Try different HTTP methods
            for method in ['GET', 'POST', 'PUT']:
                for payload_type, payloads in XSS_PAYLOADS.items():
                    for payload in payloads:
                        if payload_type in ["stored", "basic"]:
                            try:
                                # Prepare test data
                                test_data = {"comment": payload, "feedback": payload, "review": payload}
                                
                                if method == 'GET':
                                    response = self.session.get(api_url, params=test_data, timeout=self.timeout)
                                elif method == 'POST':
                                    response = self.session.post(api_url, json=test_data, timeout=self.timeout)
                                elif method == 'PUT':
                                    response = self.session.put(api_url, json=test_data, timeout=self.timeout)
                                
                                # Check if the payload was accepted
                                if response.status_code in [200, 201, 202]:
                                    # Try to retrieve the data to see if it's stored
                                    get_response = self.session.get(api_url, timeout=self.timeout)
                                    
                                    if payload in get_response.text:
                                        evidence = f"Payload stored and retrieved via {endpoint}"
                                        fix_suggestion = self.generate_xss_fix_suggestions('Stored', 'Stored')
                                        
                                        finding = {
                                            'type': 'API endpoint',
                                            'url': api_url,
                                            'method': method,
                                            'payload': payload,
                                            'payload_type': payload_type,
                                            'evidence': evidence,
                                            'fix_suggestion': fix_suggestion,
                                            'response_snippet': get_response.text[:200] + "..." if len(get_response.text) > 200 else get_response.text
                                        }
                                        self.findings.append(finding)
                                        print(f"[!] Potential stored XSS vulnerability found in API endpoint")
                                        print(f"    Endpoint: {api_url}")
                                        print(f"    Evidence: {evidence}")
                                
                            except Exception as e:
                                print(f"[!] Error testing API endpoint {api_url}: {e}")
                            
                            # Small delay between requests 
                            time.sleep(0.1)
    
    def verify_stored_xss(self, base_url):
        """Verify potential stored XSS vulnerabilities by checking if payloads persist."""
        print("[*] Verifying stored XSS vulnerabilities")
        
        for payload, info in self.stored_payloads.items():
            try:
                # Visit the page where the payload might be displayed
                time.sleep(1)  # Wait a bit for potential processing
                response = self.session.get(info['url'], timeout=self.timeout)
                
                if payload in response.text:
                    evidence = "Payload persisted and reflected on page load"
                    fix_suggestion = self.generate_xss_fix_suggestions('Stored', 'Stored')
                    
                    finding = {
                        'type': 'Stored XSS (verified)',
                        'url': info['url'],
                        'action': info['action'],
                        'field': info['field'],
                        'payload': payload,
                        'payload_type': 'stored',
                        'evidence': evidence,
                        'fix_suggestion': fix_suggestion,
                        'response_snippet': response.text[:200] + "..." if len(response.text) > 200 else response.text
                    }
                    self.findings.append(finding)
                    print(f"[!] Verified stored XSS vulnerability")
                    print(f"    URL: {info['url']}")
                    print(f"    Evidence: {evidence}")
                
            except Exception as e:
                print(f"[!] Error verifying stored XSS: {e}")
    
    def run(self, pages, forms_by_url, base_url):
        """Run all XSS tests."""
        print("[*] Starting XSS tests")
        
        # Test URL parameters on all pages
        for url, html in pages.items():
            self.test_url_params_for_xss(url)
        
        # Test all forms
        self.test_forms_for_xss(forms_by_url)
        
        # Test API endpoints for stored XSS
        self.test_api_endpoints_for_stored_xss(base_url)
        
        # Verify potential stored XSS vulnerabilities
        self.verify_stored_xss(base_url)
        
        return self.findings
    
    def generate_report(self):
        """Generate a comprehensive report of found XSS vulnerabilities."""
        if not self.findings:
            print("\n[*] No XSS vulnerabilities found.")
            return
        
        print("\n" + "="*80)
        print("XSS VULNERABILITY REPORT")
        print("="*80)
        
        # Group findings by type
        findings_by_type = {}
        for finding in self.findings:
            finding_type = finding.get('type', 'Unknown')
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)
        
        # Print findings by type
        for finding_type, findings in findings_by_type.items():
            print(f"\n--- {finding_type} ---")
            for i, finding in enumerate(findings, 1):
                print(f"\n{i}. Vulnerability Found:")
                print(f"   URL: {finding['url']}")
                
                if 'parameter' in finding:
                    print(f"   Parameter: {finding['parameter']}")
                if 'action' in finding:
                    print(f"   Form Action: {finding['action']}")
                if 'field' in finding:
                    print(f"   Field: {finding['field']}")
                if 'method' in finding:
                    print(f"   Method: {finding['method']}")
                
                print(f"   Payload: {finding['payload']}")
                print(f"   Payload Type: {finding.get('payload_type', 'unknown')}")
                print(f"   Evidence: {finding['evidence']}")
                print(f"   Suggested Fix: {finding.get('fix_suggestion', 'Implement input validation and output encoding')}")
        
        print(f"\nTotal XSS vulnerabilities found: {len(self.findings)}")
        print("="*80)