import json
from datetime import datetime

class SecurityAssessmentTool:
    def __init__(self):
        self.scanner = None
        self.exploiter = None
        self.results = {}
    
    def load_assets_from_file(self, file_path):
        """Load discovered assets from previous scans"""
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    return json.load(f)
                else:
                    return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error loading assets: {e}")
            return []
    
    def run_complete_assessment(self, assets_file, output_file=None):
        """Run complete vulnerability assessment"""
        print("Starting comprehensive security assessment...")
        
        # Load assets
        assets = self.load_assets_from_file(assets_file)
        print(f"Loaded {len(assets)} assets for assessment")
        
        # Initialize scanner
        self.scanner = VulnerabilityScanner(targets=assets, threads=15)
        
        # Run vulnerability scan
        print("\n" + "="*50)
        print("PHASE 1: Vulnerability Discovery")
        print("="*50)
        self.scanner.run_scan()
        
        # Run exploitation on found vulnerabilities
        print("\n" + "="*50)
        print("PHASE 2: Vulnerability Exploitation")
        print("="*50)
        self.run_exploitation_phase()
        
        # Generate report
        print("\n" + "="*50)
        print("PHASE 3: Report Generation")
        print("="*50)
        self.generate_report(output_file)
    
    def run_exploitation_phase(self):
        """Run exploitation on discovered vulnerabilities"""
        if not self.scanner or not self.scanner.vulnerabilities:
            print("No vulnerabilities found to exploit")
            return
        
        self.exploiter = AdvancedExploiter("")
        
        for vulnerability in self.scanner.vulnerabilities:
            if vulnerability['severity'] in ['HIGH', 'CRITICAL']:
                print(f"\nExploiting: {vulnerability['type']} at {vulnerability['target']}")
                self.exploiter.run_exploitation(
                    vulnerability['type'],
                    vulnerability['target'],
                    vulnerability['details']
                )
    
    def generate_report(self, output_file=None):
        """Generate comprehensive security report"""
        if not self.scanner:
            return
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'assets_scanned': len(self.scanner.targets),
            'vulnerabilities_found': len(self.scanner.vulnerabilities),
            'vulnerabilities': self.scanner.vulnerabilities,
            'summary': self.generate_summary()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report saved to: {output_file}")
        else:
            print(json.dumps(report, indent=2))
    
    def generate_summary(self):
        """Generate executive summary"""
        if not self.scanner:
            return {}
        
        critical_count = len([v for v in self.scanner.vulnerabilities if v['severity'] == 'CRITICAL'])
        high_count = len([v for v in self.scanner.vulnerabilities if v['severity'] == 'HIGH'])
        
        return {
            'critical_vulnerabilities': critical_count,
            'high_vulnerabilities': high_count,
            'risk_level': 'HIGH' if critical_count > 0 else 'MEDIUM' if high_count > 0 else 'LOW',
            'recommendations': self.generate_recommendations()
        }
    
    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []
        
        vuln_types = set(v['type'] for v in self.scanner.vulnerabilities)
        
        if 'SQL Injection' in vuln_types:
            recommendations.append("Implement parameterized queries and input validation")
        
        if 'XSS' in vuln_types:
            recommendations.append("Implement Content Security Policy and output encoding")
        
        if 'Directory Traversal' in vuln_types:
            recommendations.append("Implement proper file path validation and sandboxing")
        
        return recommendations

# Usage example
if __name__ == "__main__":
    assessment = SecurityAssessmentTool()
    assessment.run_complete_assessment(
        assets_file="discovered_assets.txt",
        output_file="security_assessment_report.json"
    )