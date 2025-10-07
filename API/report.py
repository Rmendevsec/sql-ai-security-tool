from core_api.api_ai_scanner.crawler import Colors

class ReportGenerator:
    def __init__(self):
        pass
    
    def print_status(self, message, status="info"):
        """Print colored status messages"""
        if status == "info":
            print(f"{Colors.BLUE}[+] {message}{Colors.END}")
        elif status == "success":
            print(f"{Colors.GREEN}[+] {message}{Colors.END}")
        elif status == "warning":
            print(f"{Colors.YELLOW}[!] {message}{Colors.END}")
        elif status == "error":
            print(f"{Colors.RED}[!] {message}{Colors.END}")
        elif status == "vuln":
            print(f"{Colors.RED}{Colors.BOLD}[VULN] {message}{Colors.END}")
        elif status == "advanced":
            print(f"{Colors.PURPLE}[*] {message}{Colors.END}")
        elif status == "data":
            print(f"{Colors.CYAN}[$] {message}{Colors.END}")
    
    def generate_report(self, vulnerabilities, sensitive_data):
        """Generate a comprehensive vulnerability report"""
        print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
        print(f"{Colors.CYAN}{Colors.BOLD}ADVANCED API SECURITY SCAN REPORT{Colors.END}")
        print(f"{Colors.CYAN}{'='*80}{Colors.END}")
        
        if not vulnerabilities:
            self.print_status("No vulnerabilities found!", "success")
            return
        
        high_count = sum(1 for v in vulnerabilities if v['severity'] == 'High')
        medium_count = sum(1 for v in vulnerabilities if v['severity'] == 'Medium')
        low_count = sum(1 for v in vulnerabilities if v['severity'] == 'Low')
        
        print(f"\n{Colors.BOLD}Summary:{Colors.END}")
        print(f"{Colors.RED}High: {high_count}{Colors.END}")
        print(f"{Colors.YELLOW}Medium: {medium_count}{Colors.END}")
        print(f"{Colors.BLUE}Low: {low_count}{Colors.END}")
        print(f"{Colors.BOLD}Total: {len(vulnerabilities)}{Colors.END}")
        
        vuln_by_type = {}
        for vuln in vulnerabilities:
            if vuln['type'] not in vuln_by_type:
                vuln_by_type[vuln['type']] = []
            vuln_by_type[vuln['type']].append(vuln)
        
        print(f"\n{Colors.BOLD}Vulnerabilities by Type:{Colors.END}")
        for vuln_type, vulns in vuln_by_type.items():
            severity_color = Colors.RED if any(v['severity'] == 'High' for v in vulns) else Colors.YELLOW if any(v['severity'] == 'Medium' for v in vulns) else Colors.BLUE
            print(f"{severity_color}{vuln_type}: {len(vulns)}{Colors.END}")
        
        self.print_status(f"\nFound {len(vulnerabilities)} vulnerabilities:", "warning")
        
        for i, vuln in enumerate(vulnerabilities, 1):
            color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW if vuln['severity'] == 'Medium' else Colors.BLUE
            print(f"\n{color}{i}. {vuln['type']} ({vuln['severity']}){Colors.END}")
            print(f"   URL: {vuln['url']}")
            print(f"   Method: {vuln['method']}")
            if vuln.get('params'):
                print(f"   Parameters: {vuln['params']}")
            print(f"   Evidence: {vuln['evidence']}")
        
        if sensitive_data:
            print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
            print(f"{Colors.CYAN}{Colors.BOLD}SENSITIVE DATA FINDINGS{Colors.END}")
            print(f"{Colors.CYAN}{'='*80}{Colors.END}")
            
            for i, data in enumerate(sensitive_data, 1):
                print(f"\n{Colors.CYAN}{i}. {data['type']}{Colors.END}")
                print(f"   URL: {data['url']}")
                print(f"   Value: {data['value'][:100]}{'...' if len(data['value']) > 100 else ''}")