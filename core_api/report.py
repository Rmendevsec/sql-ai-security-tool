"""
Report generator for API security testing results.
"""

import json
import html
from typing import Dict, List, Any
from datetime import datetime

class APIReportGenerator:
    """Generate reports for API security testing."""
    
    def __init__(self, results: Dict[str, Any]):
        self.results = results
        self.timestamp = datetime.now().isoformat()
    
    def generate_json_report(self, output_file: str = None) -> str:
        """Generate a JSON report."""
        report = {
            'metadata': {
                'generated_at': self.timestamp,
                'tool': 'Core API Security Scanner'
            },
            'results': self.results
        }
        
        json_report = json.dumps(report, indent=2)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_report)
        
        return json_report
    
    def generate_html_report(self, output_file: str = None) -> str:
        """Generate an HTML report."""
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .summary {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ background-color: #ffebee; border-left: 5px solid #d32f2f; }}
                .high {{ background-color: #fff3e0; border-left: 5px solid #f57c00; }}
                .medium {{ background-color: #fff9c4; border-left: 5px solid #ffeb3b; }}
                .low {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; }}
                .info {{ background-color: #e3f2fd; border-left: 5px solid #2196f3; }}
                pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1>API Security Scan Report</h1>
            <p>Generated at: {self.timestamp}</p>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <p>Total endpoints scanned: {len(self.results.get('endpoints', []))}</p>
                <p>Total vulnerabilities found: {self._count_vulnerabilities()}</p>
            </div>
            
            <h2>Discovered Endpoints</h2>
            <ul>
                {self._generate_endpoints_list()}
            </ul>
            
            <h2>Vulnerabilities</h2>
            {self._generate_vulnerabilities_section()}
            
            <h2>Detailed Findings</h2>
            {self._generate_detailed_findings()}
        </body>
        </html>
        """
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_template)
        
        return html_template
    
    def _count_vulnerabilities(self) -> int:
        """Count total vulnerabilities found."""
        count = 0
        for endpoint, findings in self.results.get('vulnerabilities', {}).items():
            count += len(findings)
        return count
    
    def _generate_endpoints_list(self) -> str:
        """Generate HTML list of discovered endpoints."""
        endpoints_html = []
        for endpoint in self.results.get('endpoints', []):
            endpoints_html.append(f"<li><code>{html.escape(endpoint)}</code></li>")
        return "\n".join(endpoints_html)
    
    def _generate_vulnerabilities_section(self) -> str:
        """Generate HTML section for vulnerabilities."""
        vulnerabilities = self.results.get('vulnerabilities', {})
        
        if not vulnerabilities:
            return "<p>No vulnerabilities found.</p>"
        
        vuln_html = []
        for endpoint, findings in vulnerabilities.items():
            for finding in findings:
                severity_class = finding.get('severity', 'info').lower()
                vuln_html.append(f"""
                <div class="vulnerability {severity_class}">
                    <h3>{html.escape(finding.get('type', 'Unknown'))}</h3>
                    <p><strong>Endpoint:</strong> <code>{html.escape(endpoint)}</code></p>
                    <p><strong>Severity:</strong> {html.escape(finding.get('severity', 'Unknown'))}</p>
                    <p><strong>Parameter:</strong> {html.escape(finding.get('parameter', 'N/A'))}</p>
                    <p><strong>Payload:</strong> <code>{html.escape(finding.get('payload', 'N/A'))}</code></p>
                    <p><strong>Evidence:</strong> {html.escape(finding.get('evidence', 'N/A'))}</p>
                </div>
                """)
        
        return "\n".join(vuln_html)
    
    def _generate_detailed_findings(self) -> str:
        """Generate detailed findings section."""
        details_html = []
        
        # Add authentication findings
        auth_findings = self.results.get('authentication', {})
        if auth_findings:
            details_html.append("<h3>Authentication</h3>")
            details_html.append(f"<pre>{json.dumps(auth_findings, indent=2)}</pre>")
        
        # Add technology findings
        tech_findings = self.results.get('technology', {})
        if tech_findings:
            details_html.append("<h3>Technology Stack</h3>")
            details_html.append(f"<pre>{json.dumps(tech_findings, indent=2)}</pre>")
        
        return "\n".join(details_html)
    
    def generate_pdf_report(self, output_file: str = None) -> str:
        """Generate a PDF report (requires pdfkit and wkhtmltopdf)."""
        try:
            import pdfkit
            html_report = self.generate_html_report()
            
            if output_file:
                pdfkit.from_string(html_report, output_file)
                return f"PDF report generated: {output_file}"
            else:
                # Return as base64 or save to temporary file
                return "PDF generation requires output file path"
        except ImportError:
            return "PDF generation requires pdfkit and wkhtmltopdf"