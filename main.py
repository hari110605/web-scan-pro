import argparse
import warnings
import time
from crawler import Crawler
from sqlitester import SQLiTester
from xss import XSSTester
from report_generator import SecurityReportGenerator
# from auth import AuthTester  # Commented out until auth.py is created
# from access_control import AccessControlTester  # Commented out until file is created

# Handle import of NotOpenSSLWarning with compatibility for different urllib3 versions
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    # Fallback: ignore if NotOpenSSLWarning is not available
    warnings.filterwarnings('ignore', module='urllib3')
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security-focused web crawler with SQL injection, XSS, authentication, and access control testing")
    parser.add_argument("-u", "--url", required=True, help="Base URL to crawl")
    parser.add_argument("-m", "--max-pages", type=int, default=50, help="Maximum number of pages to crawl")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--test-sqli", action="store_true", help="Enable SQL injection testing")
    parser.add_argument("--test-xss", action="store_true", help="Enable XSS testing")
    # parser.add_argument("--test-auth", action="store_true", help="Enable authentication and session testing")
    # parser.add_argument("--test-access", action="store_true", help="Enable access control and IDOR testing")
    parser.add_argument("--test-all", action="store_true", help="Enable all security tests")
    parser.add_argument("--generate-report", action="store_true", default=True, help="Generate security reports (default: True)")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports (default: reports)")
    
    args = parser.parse_args()
    
    # If test-all is specified, enable all tests
    if args.test_all:
        args.test_sqli = True
        args.test_xss = True
        # args.test_auth = True
        # args.test_access = True
    
    print("--- Running Security Web Crawler ---")
    
    # Track scan start time for duration calculation
    scan_start_time = time.time()
    
    crawler = Crawler(
        base_url=args.url, 
        max_pages=args.max_pages, 
        delay=args.delay
    )
    
    # Run the crawl
    print(f"\nStarting crawl of {args.url}...")
    results = crawler.crawl()
    
    # Print the final results of the crawl
    print("\n--- Crawl Results ---")
    print(f"Total unique pages visited: {len(results['pages'])}")
    
    # Initialize report generator
    scan_metadata = {
        'pages_scanned': len(results['pages']),
        'forms_tested': len(results['forms']),
        'scan_duration': 0  # Will be calculated at the end
    }
    
    report_generator = SecurityReportGenerator(args.url, scan_metadata)
    
    # Initialize findings storage
    all_findings = {
        'sqli': [],
        'xss': [],
        'auth': [],
        'access_control': []
    }
    
    # Run SQL injection tests if enabled
    if args.test_sqli:
        print("\n--- Starting SQL Injection Tests ---")
        sqli_tester = SQLiTester()
        sqli_findings = sqli_tester.run(results['pages'], results['forms'])
        all_findings['sqli'] = sqli_findings
        report_generator.add_findings('sqli', sqli_findings)
        sqli_tester.generate_report()
    
    # Run XSS tests if enabled
    if args.test_xss:
        print("\n--- Starting XSS Tests ---")
        xss_tester = XSSTester()
        xss_findings = xss_tester.run(results['pages'], results['forms'], args.url)
        all_findings['xss'] = xss_findings
        report_generator.add_findings('xss', xss_findings)
        xss_tester.generate_report()
    
    # Run authentication tests if enabled
    # if args.test_auth:
    #     print("\n--- Starting Authentication & Session Security Tests ---")
    #     auth_tester = AuthTester()
    #     auth_findings = auth_tester.run(results['pages'], results['forms'], args.url)
    #     all_findings['auth'] = auth_findings
    #     report_generator.add_findings('auth', auth_findings)
    #     auth_tester.generate_report()
    
    # Run access control and IDOR tests if enabled
    # if args.test_access:
    #     print("\n--- Starting Access Control & IDOR Tests ---")
    #     access_tester = AccessControlTester()
    #     access_findings = access_tester.run(results['pages'], results['forms'], args.url)
    #     all_findings['access_control'] = access_findings
    #     report_generator.add_findings('access_control', access_findings)
    #     access_tester.generate_report()
    
    # Calculate total scan duration
    scan_end_time = time.time()
    scan_duration = round(scan_end_time - scan_start_time, 2)
    scan_metadata['scan_duration'] = scan_duration
    
    # Generate comprehensive security reports
    if args.generate_report:
        print(f"\n--- Generating Security Reports ---")
        generated_reports = report_generator.generate_all_reports(args.output_dir)
        
        if generated_reports:
            print(f"\nReport generation successful! Files created in '{args.output_dir}/' directory:")
            for report_file in generated_reports:
                print(f"  - {report_file}")
        else:
            print("No reports were generated.")
    
    # Print final summary
    total_vulnerabilities = sum(len(findings) for findings in all_findings.values())
    print(f"\n--- Security Scan Complete ---")
    print(f"Scan duration: {scan_duration} seconds")
    print(f"Total vulnerabilities found: {total_vulnerabilities}")
    
    if total_vulnerabilities > 0:
        print(f"Review the generated reports for detailed findings and remediation guidance.")
    else:
        print(f"No security vulnerabilities were detected in the tested areas.")
        print(f"Note: This doesn't guarantee complete security. Continue regular assessments.")
    #     auth_tester.generate_report()
    
    # Run access control and IDOR tests if enabled
    # if args.test_access:
    #     print("\n--- Starting Access Control & IDOR Tests ---")
    #     access_tester = AccessControlTester()
    #     access_findings = access_tester.run(results['pages'], results['forms'], args.url)
    #     access_tester.generate_report()


    print("\n--- Security Crawl Complete ---")