import os
import json
import datetime
from urllib.parse import urlparse
import base64

class SecurityReportGenerator:
    """Generate comprehensive security reports in HTML and PDF formats"""
    
    def _init_(self, target_url, scan_metadata=None):
        self.target_url = target_url
        self.scan_metadata = scan_metadata or {}
        self.all_findings = {
            'sqli': [],
            'xss': [],
            'auth': [],
            'access_control': []
        }
        self.scan_summary = {
            'total_vulnerabilities': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'pages_scanned': 0,
            'forms_tested': 0,
            'scan_duration': 0
        }
        
    def add_findings(self, test_type, findings):
        """Add findings from a specific test type"""
        if test_type in self.all_findings:
            self.all_findings[test_type] = findings or []
            print(f"[*] Added {len(self.all_findings[test_type])} {test_type} findings to report")
    
    def calculate_summary(self):
        """Calculate overall scan summary statistics"""
        total_findings = 0
        severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for test_type, findings in self.all_findings.items():
            total_findings += len(findings)
            for finding in findings:
                severity = finding.get('severity', 'Medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        self.scan_summary.update({
            'total_vulnerabilities': total_findings,
            'high_severity': severity_counts['High'],
            'medium_severity': severity_counts['Medium'],
            'low_severity': severity_counts['Low'],
            'pages_scanned': self.scan_metadata.get('pages_scanned', 0),
            'forms_tested': self.scan_metadata.get('forms_tested', 0),
            'scan_duration': self.scan_metadata.get('scan_duration', 0)
        })
    
    def get_severity_color(self, severity):
        """Get color code for severity level"""
        colors = {
            'High': '#dc3545',     # Red
            'Medium': '#fd7e14',   # Orange  
            'Low': '#ffc107'       # Yellow
        }
        return colors.get(severity, '#6c757d')  # Gray for unknown
    
    def get_vulnerability_description(self, vuln_type):
        """Get detailed description for vulnerability type"""
        descriptions = {
            'sqli': {
                'name': 'SQL Injection',
                'description': 'Allows attackers to execute malicious SQL commands in the database',
                'impact': 'Data breach, data manipulation, unauthorized access to sensitive information'
            },
            'xss': {
                'name': 'Cross-Site Scripting (XSS)',
                'description': 'Allows attackers to inject malicious scripts into web pages',
                'impact': 'Session hijacking, credential theft, defacement, malware distribution'
            },
            'auth': {
                'name': 'Authentication Vulnerabilities',
                'description': 'Weaknesses in authentication and session management mechanisms',
                'impact': 'Account takeover, unauthorized access, privilege escalation'
            },
            'access_control': {
                'name': 'Access Control Vulnerabilities',
                'description': 'Improper enforcement of access restrictions and authorization',
                'impact': 'Unauthorized data access, privilege escalation, data exposure'
            }
        }
        return descriptions.get(vuln_type, {
            'name': vuln_type.title(),
            'description': f'{vuln_type} vulnerability found during security assessment',
            'impact': 'Potential security risk requiring investigation'
        })
    
    def generate_html_report(self, output_file='security_report.html'):
        """Generate comprehensive HTML security report"""
        print(f"[*] Generating HTML security report: {output_file}")
        
        self.calculate_summary()
        
        # HTML template with embedded CSS and JavaScript
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebScanPro Security Report - {urlparse(self.target_url).netloc}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 1rem;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }}
        
        .summary-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .summary-card h3 {{
            color: #667eea;
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}
        
        .summary-card p {{
            color: #6c757d;
            font-weight: 500;
        }}
        
        .severity-high {{ border-left-color: #dc3545; }}
        .severity-medium {{ border-left-color: #fd7e14; }}
        .severity-low {{ border-left-color: #ffc107; }}
        
        .chart-container {{
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 2rem 0;
            text-align: center;
        }}
        
        .vulnerability-section {{
            margin: 2rem 0;
        }}
        
        .vuln-type-header {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px 10px 0 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        
        .vuln-type-header h2 {{
            color: #667eea;
            margin-bottom: 0.5rem;
        }}
        
        .vuln-finding {{
            background: white;
            margin: 0.5rem 0;
            padding: 1.5rem;
            border-radius: 0 0 10px 10px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
            border-left: 4px solid #e9ecef;
        }}
        
        .vuln-finding.high {{ border-left-color: #dc3545; }}
        .vuln-finding.medium {{ border-left-color: #fd7e14; }}
        .vuln-finding.low {{ border-left-color: #ffc107; }}
        
        .severity-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            color: white;
            font-size: 0.875rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-high-bg {{ background-color: #dc3545; }}
        .severity-medium-bg {{ background-color: #fd7e14; }}
        .severity-low-bg {{ background-color: #ffc107; color: #212529; }}
        
        .url-text {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.9rem;
            word-break: break-all;
        }}
        
        .fix-suggestion {{
            background: #e8f5e8;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 1rem;
            margin-top: 1rem;
        }}
        
        .fix-suggestion h4 {{
            color: #155724;
            margin-bottom: 0.5rem;
        }}
        
        .no-vulnerabilities {{
            text-align: center;
            padding: 3rem;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .footer {{
            background: #343a40;
            color: white;
            padding: 2rem 0;
            text-align: center;
            margin-top: 3rem;
        }}
        
        .scan-info {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 2rem 0;
        }}
        
        .scan-info h3 {{
            color: #667eea;
            margin-bottom: 1rem;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .info-item {{
            padding: 0.5rem;
            border-left: 3px solid #667eea;
            background: #f8f9fa;
        }}
        
        .info-item strong {{
            display: block;
            color: #495057;
            margin-bottom: 0.25rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1>WebScanPro Security Report</h1>
            <p>Security Assessment for {self.target_url}</p>
            <p>Generated on {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
        </div>
    </div>
    
    <div class="container">
        <div class="scan-info">
            <h3>Scan Information</h3>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Target URL</strong>
                    <span class="url-text">{self.target_url}</span>
                </div>
                <div class="info-item">
                    <strong>Pages Scanned</strong>
                    {self.scan_summary['pages_scanned']}
                </div>
                <div class="info-item">
                    <strong>Forms Tested</strong>
                    {self.scan_summary['forms_tested']}
                </div>
                <div class="info-item">
                    <strong>Scan Duration</strong>
                    {self.scan_summary['scan_duration']} seconds
                </div>
            </div>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>{self.scan_summary['total_vulnerabilities']}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="summary-card severity-high">
                <h3>{self.scan_summary['high_severity']}</h3>
                <p>High Severity</p>
            </div>
            <div class="summary-card severity-medium">
                <h3>{self.scan_summary['medium_severity']}</h3>
                <p>Medium Severity</p>
            </div>
            <div class="summary-card severity-low">
                <h3>{self.scan_summary['low_severity']}</h3>
                <p>Low Severity</p>
            </div>
        </div>
        
        {self.generate_vulnerability_sections()}
    </div>
    
    <div class="footer">
        <div class="container">
            <p>&copy; 2024 WebScanPro - Security Assessment Tool</p>
            <p>Report generated automatically - Review findings manually before taking action</p>
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[+] HTML report generated successfully: {output_file}")
            return output_file
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")
            return None
    
    def generate_vulnerability_sections(self):
        """Generate HTML sections for each vulnerability type"""
        sections_html = ""
        
        if self.scan_summary['total_vulnerabilities'] == 0:
            return '''
            <div class="no-vulnerabilities">
                <h2>🎉 No Vulnerabilities Found</h2>
                <p>Great news! The security scan did not identify any vulnerabilities in the tested areas.</p>
                <p><strong>Note:</strong> This doesn't guarantee complete security. Continue regular security assessments.</p>
            </div>
            '''
        
        for test_type, findings in self.all_findings.items():
            if findings:
                vuln_info = self.get_vulnerability_description(test_type)
                sections_html += f'''
                <div class="vulnerability-section">
                    <div class="vuln-type-header">
                        <h2>{vuln_info['name']} ({len(findings)} findings)</h2>
                        <p><strong>Description:</strong> {vuln_info['description']}</p>
                        <p><strong>Potential Impact:</strong> {vuln_info['impact']}</p>
                    </div>
                '''
                
                for i, finding in enumerate(findings, 1):
                    severity = finding.get('severity', 'Medium').lower()
                    sections_html += f'''
                    <div class="vuln-finding {severity}">
                        <h4>Finding #{i}: {finding.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                        <p><strong>Severity:</strong> 
                            <span class="severity-badge severity-{severity}-bg">{finding.get('severity', 'Medium')}</span>
                        </p>
                        <p><strong>URL:</strong> <span class="url-text">{finding.get('url', 'N/A')}</span></p>
                        
                        {self.generate_finding_details(finding)}
                        
                        <div class="fix-suggestion">
                            <h4>🛠 Suggested Fix</h4>
                            <p>{finding.get('fix_suggestion', 'Review and implement appropriate security controls.')}</p>
                        </div>
                    </div>
                    '''
                
                sections_html += '</div>'
        
        return sections_html
    
    def generate_finding_details(self, finding):
        """Generate specific details for a finding"""
        details_html = ""
        
        if 'evidence' in finding:
            details_html += f'<p><strong>Evidence:</strong> {finding["evidence"]}</p>'
        
        if 'payload' in finding:
            details_html += f'<p><strong>Payload:</strong> <code>{finding["payload"]}</code></p>'
        
        if 'parameter' in finding:
            details_html += f'<p><strong>Parameter:</strong> {finding["parameter"]}</p>'
        
        if 'method' in finding:
            details_html += f'<p><strong>HTTP Method:</strong> {finding["method"]}</p>'
        
        if 'form_action' in finding:
            details_html += f'<p><strong>Form Action:</strong> <span class="url-text">{finding["form_action"]}</span></p>'
        
        return details_html
    
    def generate_json_report(self, output_file='security_report.json'):
        """Generate JSON report for programmatic use"""
        print(f"[*] Generating JSON security report: {output_file}")
        
        self.calculate_summary()
        
        report_data = {
            'scan_metadata': {
                'target_url': self.target_url,
                'scan_date': datetime.datetime.now().isoformat(),
                'tool_name': 'WebScanPro',
                'tool_version': '1.0.0'
            },
            'scan_summary': self.scan_summary,
            'vulnerabilities': self.all_findings,
            'recommendations': self.get_general_recommendations()
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            print(f"[+] JSON report generated successfully: {output_file}")
            return output_file
        except Exception as e:
            print(f"[!] Error generating JSON report: {e}")
            return None
    
    def generate_csv_summary(self, output_file='vulnerability_summary.csv'):
        """Generate CSV summary for spreadsheet analysis"""
        print(f"[*] Generating CSV summary: {output_file}")
        
        try:
            import csv
            
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Type', 'Severity', 'URL', 'Evidence', 'Fix_Suggestion']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for test_type, findings in self.all_findings.items():
                    for finding in findings:
                        writer.writerow({
                            'Type': finding.get('type', test_type),
                            'Severity': finding.get('severity', 'Medium'),
                            'URL': finding.get('url', ''),
                            'Evidence': finding.get('evidence', ''),
                            'Fix_Suggestion': finding.get('fix_suggestion', '')
                        })
            
            print(f"[+] CSV summary generated successfully: {output_file}")
            return output_file
        except Exception as e:
            print(f"[!] Error generating CSV summary: {e}")
            return None
    
    def get_general_recommendations(self):
        """Get general security recommendations based on findings"""
        recommendations = [
            "Implement input validation and output encoding for all user inputs",
            "Use parameterized queries to prevent SQL injection attacks",
            "Enable proper authentication and session management controls",
            "Implement proper access controls and authorization checks",
            "Keep software and dependencies updated to latest secure versions",
            "Use HTTPS everywhere and implement proper SSL/TLS configuration",
            "Implement Content Security Policy (CSP) headers to prevent XSS",
            "Regular security assessments and penetration testing",
            "Security awareness training for development teams",
            "Implement proper error handling that doesn't reveal system information"
        ]
        
        # Add specific recommendations based on found vulnerabilities
        specific_recs = []
        if self.all_findings['sqli']:
            specific_recs.append("Immediately review and fix SQL injection vulnerabilities - use parameterized queries")
        if self.all_findings['xss']:
            specific_recs.append("Implement XSS protection through input validation and output encoding")
        if self.all_findings['auth']:
            specific_recs.append("Strengthen authentication mechanisms and session management")
        if self.all_findings['access_control']:
            specific_recs.append("Review and implement proper access control mechanisms")
        
        return specific_recs + recommendations
    
    def generate_pdf_report(self, output_file='security_report.pdf'):
        """Generate PDF report using HTML to PDF conversion"""
        print(f"[*] Generating PDF security report: {output_file}")
        
        try:
            # Try to import weasyprint for PDF generation
            try:
                import weasyprint
                
                # Generate HTML content first
                html_content = self.generate_html_content_for_pdf()
                
                # Convert HTML to PDF
                weasyprint.HTML(string=html_content).write_pdf(output_file)
                print(f"[+] PDF report generated successfully: {output_file}")
                return output_file
                
            except ImportError:
                print("[!] weasyprint not installed. Install with: pip install weasyprint")
                
                # Fallback: Generate HTML and suggest manual PDF conversion
                html_file = output_file.replace('.pdf', '_for_pdf.html')
                self.generate_html_report(html_file)
                print(f"[*] Generated HTML file instead: {html_file}")
                print(f"[*] You can manually convert to PDF using a browser or online converter")
                return html_file
                
        except Exception as e:
            print(f"[!] Error generating PDF report: {e}")
            return None
    
    def generate_html_content_for_pdf(self):
        """Generate HTML content optimized for PDF conversion"""
        self.calculate_summary()
        
        # PDF-optimized HTML with better styling
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WebScanPro Security Report - {urlparse(self.target_url).netloc}</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm 1.5cm;
            @top-center {{
                content: "WebScanPro Security Report";
                font-size: 10pt;
                color: #666;
            }}
            @bottom-center {{
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10pt;
                color: #666;
            }}
        }}
        
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.4;
            color: #333;
            font-size: 11pt;
        }}
        
        .header {{
            text-align: center;
            padding-bottom: 20px;
            border-bottom: 2px solid #667eea;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            color: #667eea;
            font-size: 24pt;
            margin-bottom: 10px;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        
        .summary-card {{
            border: 1px solid #ddd;
            padding: 15px;
            text-align: center;
            border-radius: 5px;
        }}
        
        .summary-card h3 {{
            font-size: 18pt;
            margin-bottom: 5px;
            color: #667eea;
        }}
        
        .vulnerability-section {{
            page-break-before: auto;
            margin: 30px 0;
        }}
        
        .vuln-type-header {{
            background: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #667eea;
            margin-bottom: 10px;
        }}
        
        .vuln-finding {{
            margin: 10px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-left: 4px solid #fd7e14;
        }}
        
        .vuln-finding.high {{ border-left-color: #dc3545; }}
        .vuln-finding.medium {{ border-left-color: #fd7e14; }}
        .vuln-finding.low {{ border-left-color: #ffc107; }}
        
        .severity-badge {{
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 9pt;
            font-weight: bold;
            color: white;
        }}
        
        .severity-high-bg {{ background-color: #dc3545; }}
        .severity-medium-bg {{ background-color: #fd7e14; }}
        .severity-low-bg {{ background-color: #ffc107; color: #000; }}
        
        .url-text {{
            font-family: monospace;
            background: #f8f9fa;
            padding: 2px 4px;
            font-size: 9pt;
            word-break: break-all;
        }}
        
        .fix-suggestion {{
            background: #e8f5e8;
            border: 1px solid #c3e6cb;
            padding: 10px;
            margin-top: 10px;
        }}
        
        .page-break {{ page-break-before: always; }}
        
        .toc {{
            margin: 20px 0;
        }}
        
        .toc ul {{
            list-style: none;
            padding: 0;
        }}
        
        .toc li {{
            margin: 5px 0;
            padding: 5px;
            border-bottom: 1px dotted #ccc;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>WebScanPro Security Report</h1>
        <p><strong>Target:</strong> {self.target_url}</p>
        <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p>
    </div>
    
    <div class="summary-grid">
        <div class="summary-card">
            <h3>{self.scan_summary['total_vulnerabilities']}</h3>
            <p>Total Vulnerabilities</p>
        </div>
        <div class="summary-card">
            <h3>{self.scan_summary['high_severity']}</h3>
            <p>High Severity</p>
        </div>
        <div class="summary-card">
            <h3>{self.scan_summary['medium_severity']}</h3>
            <p>Medium Severity</p>
        </div>
        <div class="summary-card">
            <h3>{self.scan_summary['low_severity']}</h3>
            <p>Low Severity</p>
        </div>
    </div>
    
    <div class="page-break"></div>
    
    {self.generate_vulnerability_sections()}
</body>
</html>"""
        
    def generate_all_reports(self, output_dir='reports'):
        """Generate all report formats"""
        print(f"[*] Generating comprehensive security reports in directory: {output_dir}")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp for unique filenames
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urlparse(self.target_url).netloc.replace(':', '_')
        
        reports_generated = []
        
        # Generate HTML report
        html_file = os.path.join(output_dir, f'security_report_{domain}_{timestamp}.html')
        if self.generate_html_report(html_file):
            reports_generated.append(html_file)
        
        # Generate PDF report (if weasyprint is available)
        pdf_file = os.path.join(output_dir, f'security_report_{domain}_{timestamp}.pdf')
        pdf_result = self.generate_pdf_report(pdf_file)
        if pdf_result:
            reports_generated.append(pdf_result)
        
        # Generate JSON report
        json_file = os.path.join(output_dir, f'security_report_{domain}_{timestamp}.json')
        if self.generate_json_report(json_file):
            reports_generated.append(json_file)
        
        # Generate CSV summary
        csv_file = os.path.join(output_dir, f'vulnerability_summary_{domain}_{timestamp}.csv')
        if self.generate_csv_summary(csv_file):
            reports_generated.append(csv_file)
        
        # Generate executive summary
        exec_summary_file = os.path.join(output_dir, f'executive_summary_{domain}_{timestamp}.txt')
        if self.generate_executive_summary(exec_summary_file):
            reports_generated.append(exec_summary_file)
        
        print(f"\n[+] Report generation complete! Generated {len(reports_generated)} reports:")
        for report in reports_generated:
            print(f"    - {report}")
        
        return reports_generated
    
    def generate_executive_summary(self, output_file='executive_summary.txt'):
        """Generate executive summary for management"""
        print(f"[*] Generating executive summary: {output_file}")
        
        self.calculate_summary()
        
        summary_content = f"""
WEBSCANPRO SECURITY ASSESSMENT - EXECUTIVE SUMMARY
================================================================

TARGET: {self.target_url}
ASSESSMENT DATE: {datetime.datetime.now().strftime('%B %d, %Y')}
TOOL: WebScanPro v1.0.0

ASSESSMENT OVERVIEW
------------------
Pages Scanned: {self.scan_summary['pages_scanned']}
Forms Tested: {self.scan_summary['forms_tested']}
Assessment Duration: {self.scan_summary['scan_duration']} seconds

SECURITY FINDINGS SUMMARY
-------------------------
Total Vulnerabilities Found: {self.scan_summary['total_vulnerabilities']}
- High Severity: {self.scan_summary['high_severity']}
- Medium Severity: {self.scan_summary['medium_severity']}
- Low Severity: {self.scan_summary['low_severity']}

RISK ASSESSMENT
--------------
{self.generate_risk_assessment()}

VULNERABILITY BREAKDOWN
----------------------
{self.generate_vulnerability_breakdown()}

IMMEDIATE ACTION ITEMS
---------------------
{self.generate_immediate_actions()}

RECOMMENDED NEXT STEPS
---------------------
{self.generate_next_steps()}

================================================================
This summary provides a high-level overview. Refer to the detailed 
HTML/PDF reports for complete technical information and specific 
remediation guidance.
================================================================
"""
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            print(f"[+] Executive summary generated successfully: {output_file}")
            return output_file
        except Exception as e:
            print(f"[!] Error generating executive summary: {e}")
            return None
    
    def generate_risk_assessment(self):
        """Generate risk assessment based on findings"""
        high_count = self.scan_summary['high_severity']
        medium_count = self.scan_summary['medium_severity']
        total_count = self.scan_summary['total_vulnerabilities']
        
        if high_count > 0:
            risk_level = "HIGH RISK"
            risk_desc = f"The assessment identified {high_count} high-severity vulnerabilities that pose immediate security risks and require urgent attention."
        elif medium_count > 5:
            risk_level = "MEDIUM-HIGH RISK"
            risk_desc = f"The assessment found {medium_count} medium-severity issues that collectively represent a significant security concern."
        elif total_count > 0:
            risk_level = "MEDIUM RISK" 
            risk_desc = f"The assessment identified {total_count} security issues that should be addressed to improve overall security posture."
        else:
            risk_level = "LOW RISK"
            risk_desc = "No significant security vulnerabilities were identified in the tested areas."
        
        return f"Overall Risk Level: {risk_level}\n{risk_desc}"
    
    def generate_vulnerability_breakdown(self):
        """Generate vulnerability type breakdown"""
        breakdown = ""
        
        for test_type, findings in self.all_findings.items():
            if findings:
                vuln_info = self.get_vulnerability_description(test_type)
                severity_counts = {'High': 0, 'Medium': 0, 'Low': 0}
                
                for finding in findings:
                    severity = finding.get('severity', 'Medium')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                breakdown += f"\n{vuln_info['name']}: {len(findings)} findings\n"
                breakdown += f"  - High: {severity_counts['High']}, Medium: {severity_counts['Medium']}, Low: {severity_counts['Low']}\n"
                breakdown += f"  - Impact: {vuln_info['impact']}\n"
        
        if not breakdown:
            breakdown = "No vulnerabilities found in tested categories."
        
        return breakdown
    
    def generate_immediate_actions(self):
        """Generate immediate action items"""
        actions = []
        
        if self.scan_summary['high_severity'] > 0:
            actions.append(f"1. URGENT: Address {self.scan_summary['high_severity']} high-severity vulnerabilities immediately")
        
        if self.all_findings['sqli']:
            actions.append("2. CRITICAL: Review and fix SQL injection vulnerabilities - implement parameterized queries")
        
        if self.all_findings['xss']:
            actions.append("3. IMPORTANT: Implement XSS protection through input validation and output encoding")
        
        if self.all_findings['auth']:
            actions.append("4. Review authentication mechanisms and strengthen session management")
        
        if self.all_findings['access_control']:
            actions.append("5. Implement proper access control and authorization checks")
        
        if not actions:
            actions.append("1. Continue regular security assessments to maintain security posture")
            actions.append("2. Implement additional security controls as preventive measures")
        
        return "\n".join(actions)
    
    def generate_next_steps(self):
        """Generate recommended next steps"""
        steps = [
            "1. Review detailed technical reports for specific remediation guidance",
            "2. Prioritize fixes based on severity levels and business impact",
            "3. Implement security fixes in development environment first",
            "4. Conduct regression testing after implementing fixes",
            "5. Perform follow-up security assessment to verify fixes",
            "6. Implement continuous security monitoring and regular assessments",
            "7. Provide security training for development and operations teams",
            "8. Establish secure development lifecycle (SDLC) practices"
        ]
        
        return "\n".join(steps)
        """Generate all report formats"""
        print(f"[*] Generating comprehensive security reports in directory: {output_dir}")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate timestamp for unique filenames
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = urlparse(self.target_url).netloc.replace(':', '_')
        
        reports_generated = []
        
        # Generate HTML report
        html_file = os.path.join(output_dir, f'security_report_{domain}_{timestamp}.html')
        if self.generate_html_report(html_file):
            reports_generated.append(html_file)
        
        # Generate JSON report
        json_file = os.path.join(output_dir, f'security_report_{domain}_{timestamp}.json')
        if self.generate_json_report(json_file):
            reports_generated.append(json_file)
        
        # Generate CSV summary
        csv_file = os.path.join(output_dir, f'vulnerability_summary_{domain}_{timestamp}.csv')
        if self.generate_csv_summary(csv_file):
            reports_generated.append(csv_file)
        
        print(f"\n[+] Report generation complete! Generated {len(reports_generated)} reports:")
        for report in reports_generated:
            print(f"    - {report}")
        
        return reports_generated
    