import argparse
import warnings
from crawler import Crawler
from sqltester import SQLiTester
from xsstester import XSSTester

# Handle import of NotOpenSSLWarning with compatibility for different urllib3 versions
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    # Fallback: ignore if NotOpenSSLWarning is not available
    warnings.filterwarnings('ignore', module='urllib3')
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security-focused web crawler with SQL injection and XSS testing")
    parser.add_argument("-u", "--url", required=True, help="Base URL to crawl")
    parser.add_argument("-m", "--max-pages", type=int, default=50, help="Maximum number of pages to crawl")
    parser.add_argument("-d", "--delay", type=float, default=0.5, help="Delay between requests in seconds")
    parser.add_argument("--test-sqli", action="store_true", help="Enable SQL injection testing")
    parser.add_argument("--test-xss", action="store_true", help="Enable XSS testing")
    
    args = parser.parse_args()
    
    print("--- Running Security Web Crawler ---")
    
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
    
    # Run SQL injection tests if enabled
    if args.test_sqli:
        print("\n--- Starting SQL Injection Tests ---")
        sqli_tester = SQLiTester()
        sqli_findings = sqli_tester.run(results['pages'], results['forms'])
        sqli_tester.generate_report()
    
    # Run XSS tests if enabled
    if args.test_xss:
        print("\n--- Starting XSS Tests ---")
        xss_tester = XSSTester()
        xss_findings = xss_tester.run(results['pages'], results['forms'], args.url)
        xss_tester.generate_report()

    print("\n--- Security Crawl Complete ---")