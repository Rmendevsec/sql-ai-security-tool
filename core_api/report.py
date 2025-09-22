"""
Report Generator - Creates security assessment reports
"""

import json
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger(__name__)

class ReportGenerator:
    def __init__(self):
        self.findings = []
    
    def add_findings(self, findings):
        """Add findings to the report"""
        self.findings.extend(findings)
    
    def generate_json(self):
        """Generate JSON report"""
        report = {
            "generated_at": datetime.now().isoformat(),
            "findings": self.findings,
            "summary": {
                "total": len(self.findings),
                "by_severity": {
                    "High": len([f for f in self.findings if f.get("severity") == "High"]),
                    "Medium": len([f for f in self.findings if f.get("severity") == "Medium"]),
                    "Low": len([f for f in self.findings if f.get("severity") == "Low"])
                },
                "by_type": {}
            }
        }
        
        # Count findings by type
        for finding in self.findings:
            finding_type = finding.get("type", "Unknown")
            if finding_type not in report["summary"]["by_type"]:
                report["summary"]["by_type"][finding_type] = 0
            report["summary"]["by_type"][finding_type] += 1
        
        return json.dumps(report, indent=2)
    
    def generate_html(self):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>API Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #f4f4f4; padding: 20px; border-radius: 5px; }}
                .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .high {{ border-left: 5px solid #dc3545; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .severity-high {{ color: #dc3545; font-weight: bold; }}
                .severity-medium {{ color: #ffc107; font-weight: bold; }}
                .severity-low {{ color: #28a745; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>API Security Assessment Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Findings: {len(self.findings)}</p>
            </div>
        """
        
        # Group findings by severity
        high_findings = [f for f in self.findings if f.get("severity") == "High"]
        medium_findings = [f for f in self.findings if f.get("severity") == "Medium"]
        low_findings = [f for f in self.findings if f.get("severity") == "Low"]
        
        # High severity findings
        if high_findings:
            html += "<h2>High Severity Findings</h2>"
            for finding in high_findings:
                html += f"""
                <div class="finding high">
                    <h3>{finding.get('type')} <span class="severity-high">[High]</span></h3>
                    <p><strong>URL:</strong> {finding.get('url')}</p>
                    <p><strong>Method:</strong> {finding.get('method')}</p>
                    <p><strong>Evidence:</strong> {finding.get('evidence')}</p>
                    <p><strong>Parameters:</strong> {finding.get('params')}</p>
                </div>
                """
        
        # Medium severity findings
        if medium_findings:
            html += "<h2>Medium Severity Findings</h2>"
            for finding in medium_findings:
                html += f"""
                <div class="finding medium">
                    <h3>{finding.get('type')} <span class="severity-medium">[Medium]</span></h3>
                    <p><strong>URL:</strong> {finding.get('url')}</p>
                    <p><strong>Method:</strong> {finding.get('method')}</p>
                    <p><strong>Evidence:</strong> {finding.get('evidence')}</p>
                    <p><strong>Parameters:</strong> {finding.get('params')}</p>
                </div>
                """
        
        # Low severity findings
        if low_findings:
            html += "<h2>Low Severity Findings</h2>"
            for finding in low_findings:
                html += f"""
                <div class="finding low">
                    <h3>{finding.get('type')} <span class="severity-low">[Low]</span></h3>
                    <p><strong>URL:</strong> {finding.get('url')}</p>
                    <p><strong>Method:</strong> {finding.get('method')}</p>
                    <p><strong>Evidence:</strong> {finding.get('evidence')}</p>
                    <p><strong>Parameters:</strong> {finding.get('params')}</p>
                </div>
                """
        
        html += "</body></html>"
        return html
    
    def generate_markdown(self):
        """Generate Markdown report"""
        md = f"""
# API Security Assessment Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Total Findings**: {len(self.findings)}

## Summary

- **High Severity**: {len([f for f in self.findings if f.get("severity") == "High"])}
- **Medium Severity**: {len([f for f in self.findings if f.get("severity") == "Medium"])}
- **Low Severity**: {len([f for f in self.findings if f.get("severity") == "Low"])}

## Findings
"""
        
        # Group findings by severity
        for severity in ["High", "Medium", "Low"]:
            severity_findings = [f for f in self.findings if f.get("severity") == severity]
            if severity_findings:
                md += f"\n### {severity} Severity Findings\n"
                for i, finding in enumerate(severity_findings, 1):
                    md += f"""
#### {i}. {finding.get('type')}

- **URL**: {finding.get('url')}
- **Method**: {finding.get('method')}
- **Evidence**: {finding.get('evidence')}
- **Parameters**: {finding.get('params')}

"""
        
        return md
    
    def generate_report(self, format="markdown"):
        """Generate report in specified format"""
        if format.lower() == "json":
            return self.generate_json()
        elif format.lower() == "html":
            return self.generate_html()
        else:
            return self.generate_markdown()