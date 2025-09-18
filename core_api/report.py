import json
import html
from datetime import datetime
from ..utils.logger import Logger

class APIReport:
    def __init__(self):
        self.logger = Logger(__name__)
        self.findings = []
    
    def add_finding(self, finding):
        """Add a finding to the report"""
        finding['timestamp'] = datetime.now().isoformat()
        self.findings.append(finding)
        self.logger.warning(f"VULNERABILITY: {finding['type']} at {finding['url']}")
    
    def generate_json_report(self, filename=None):
        """Generate a JSON report"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "findings": self.findings
        }
        
        if filename:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
        
        return json.dumps(report, indent=2)
    
    def generate_html_report(self, filename=None):
        """Generate an HTML report"""
        severity_colors = {
            "High": "danger",
            "Medium": "warning",
            "Low": "info"
        }
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Security Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <style>
                .vuln-card {{ margin-bottom: 20px; }}
                .severity-high {{ border-left: 5px solid #dc3545; }}
                .severity-medium {{ border-left: 5px solid #ffc107; }}
                .severity-low {{ border-left: 5px solid #0dcaf0; }}
            </style>
        </head>
        <body>
            <div class="container mt-5">
                <h1 class="text-center mb-4">API Security Scan Report</h1>
                <p class="text-center">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="row mb-4">
                    <div class="col-md-4">
                        <div class="card bg-danger text-white text-center">
                            <div class="card-body">
                                <h5 class="card-title">High</h5>
                                <h3 class="card-text">{len([f for f in self.findings if f['severity'] == 'High'])}</h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-warning text-dark text-center">
                            <div class="card-body">
                                <h5 class="card-title">Medium</h5>
                                <h3 class="card-text">{len([f for f in self.findings if f['severity'] == 'Medium'])}</h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-info text-white text-center">
                            <div class="card-body">
                                <h5 class="card-title">Low</h5>
                                <h3 class="card-text">{len([f for f in self.findings if f['severity'] == 'Low'])}</h3>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h2 class="mb-3">Findings</h2>
        """
        
        for finding in self.findings:
            severity_class = severity_colors.get(finding['severity'], '')
            
            html_content += f"""
                <div class="card vuln-card severity-{finding['severity'].lower()} {severity_class}">
                    <div class="card-body">
                        <h5 class="card-title">
                            <span class="badge bg-{severity_colors.get(finding['severity'], 'secondary')}">
                                {finding['severity']}
                            </span>
                            {html.escape(finding['type'])}
                        </h5>
                        <h6 class="card-subtitle mb-2 text-muted">
                            URL: {html.escape(finding['url'])}
                        </h6>
                        <p class="card-text">
                            <strong>Method:</strong> {finding.get('method', 'N/A')}<br>
                            <strong>Parameter:</strong> {finding.get('parameter', 'N/A')}<br>
                            <strong>Payload:</strong> <code>{html.escape(str(finding.get('payload', 'N/A')))}</code><br>
                            <strong>Evidence:</strong> {html.escape(finding.get('evidence', 'N/A'))}
                        </p>
                        <small class="text-muted">
                            Detected at: {finding.get('timestamp', 'N/A')}
                        </small>
                    </div>
                </div>
            """
        
        html_content += """
            </div>
            <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
        </body>
        </html>
        """
        
        if filename:
            with open(filename, 'w') as f:
                f.write(html_content)
        
        return html_content
    
    def generate_markdown_report(self, filename=None):
        """Generate a Markdown report"""
        markdown = f"""# API Security Scan Report\n\n"""
        markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Summary
        markdown += "## Summary\n\n"
        markdown += f"- **High Severity**: {len([f for f in self.findings if f['severity'] == 'High'])}\n"
        markdown += f"- **Medium Severity**: {len([f for f in self.findings if f['severity'] == 'Medium'])}\n"
        markdown += f"- **Low Severity**: {len([f for f in self.findings if f['severity'] == 'Low'])}\n"
        markdown += f"- **Total Findings**: {len(self.findings)}\n\n"
        
        # Findings
        markdown += "## Findings\n\n"
        
        for finding in self.findings:
            severity_emoji = {
                "High": "🔴",
                "Medium": "🟡",
                "Low": "🔵"
            }.get(finding['severity'], "⚪")
            
            markdown += f"### {severity_emoji} {finding['type']} ({finding['severity']})\n\n"
            markdown += f"- **URL**: {finding['url']}\n"
            markdown += f"- **Method**: {finding.get('method', 'N/A')}\n"
            markdown += f"- **Parameter**: {finding.get('parameter', 'N/A')}\n"
            markdown += f"- **Payload**: `{finding.get('payload', 'N/A')}`\n"
            markdown += f"- **Evidence**: {finding.get('evidence', 'N/A')}\n"
            markdown += f"- **Timestamp**: {finding.get('timestamp', 'N/A')}\n\n"
        
        if filename:
            with open(filename, 'w') as f:
                f.write(markdown)
        
        return markdown