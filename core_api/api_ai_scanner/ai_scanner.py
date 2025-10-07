import requests
import json
import pickle
import argparse
from urllib.parse import urljoin
import warnings
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Suppress SSL warnings
warnings.filterwarnings('ignore', category=urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AIAPIFinder:
    def __init__(self, max_threads=20, timeout=5):
        self.max_threads = max_threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; AI-APIScanner/1.0)'
        })
        self.session.verify = False
        
        # Load AI model
        self.ai_model = self.load_ai_model()
    
    def load_ai_model(self):
        """Load the trained AI model"""
        try:
            with open('api_ai_model.pkl', 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            print("AI model not found. Please run train_ai.py first.")
            return None
    
    def ai_suggest_endpoints(self, user_description, top_k=15):
        """Use AI to suggest endpoints based on description"""
        if not self.ai_model:
            print("AI model not available. Using default endpoints.")
            return self.get_default_endpoints()
        
        from sentence_transformers import SentenceTransformer
        from sklearn.metrics.pairwise import cosine_similarity
        import numpy as np
        
        model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Encode user input
        input_embedding = model.encode([user_description])
        
        # Calculate similarity
        similarities = cosine_similarity(input_embedding, self.ai_model['embeddings'])[0]
        
        # Get top matches
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        suggestions = []
        for idx in top_indices:
            if similarities[idx] > 0.1:
                suggestions.append(self.ai_model['endpoints'][idx])
        
        return list(set(suggestions))  # Remove duplicates
    
    def get_default_endpoints(self):
        """Fallback endpoints if AI is not available"""
        return [
            '/api/v1/auth/login',
            '/api/v1/users',
            '/api/v1/products', 
            '/admin',
            '/upload',
            '/search',
            '/api',
            '/graphql'
        ]
    
    def scan_endpoint(self, endpoint, base_url):
        """Scan a single endpoint"""
        full_url = urljoin(base_url, endpoint)
        
        methods = ['GET', 'POST']
        results = []
        
        for method in methods:
            try:
                response = self.session.request(
                    method, full_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if response.status_code not in [404, 400]:
                    results.append({
                        'endpoint': endpoint,
                        'method': method,
                        'status': response.status_code,
                        'url': full_url,
                        'size': len(response.content)
                    })
                    
            except Exception:
                continue
        
        return results
    
    def smart_scan(self, target_url, user_description):
        """Perform AI-enhanced scanning"""
        print(f"[AI] Scanning: {target_url}")
        print(f"[AI] User description: '{user_description}'")
        
        # Get AI suggestions
        ai_suggestions = self.ai_suggest_endpoints(user_description)
        print(f"[AI] Suggested {len(ai_suggestions)} endpoints:")
        
        for i, endpoint in enumerate(ai_suggestions, 1):
            print(f"  {i}. {endpoint}")
        
        # Scan the suggested endpoints
        print(f"\n[*] Scanning {len(ai_suggestions)} AI-suggested endpoints...")
        
        all_results = []
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self.scan_endpoint, endpoint, target_url): endpoint 
                for endpoint in ai_suggestions
            }
            
            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                        for result in results:
                            status = result['status']
                            if status == 200:
                                color = '✓'
                            elif 300 <= status < 400:
                                color = '→'
                            else:
                                color = '!'
                            print(f"[{color}] {result['method']} {result['endpoint']} - Status: {status}")
                except Exception:
                    pass
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description='AI-Enhanced API Endpoint Finder')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('description', help='Description of what you\'re looking for (e.g., "user login system")')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        return
    
    # Create scanner and run
    scanner = AIAPIFinder(max_threads=args.threads)
    
    print("AI-Enhanced API Endpoint Scanner")
    print("=" * 60)
    
    results = scanner.smart_scan(args.url, args.description)
    
    # Print summary
    print(f"\n{'=' * 60}")
    print("SCAN SUMMARY")
    print(f"{'=' * 60}")
    print(f"Target: {args.url}")
    print(f"Search: {args.description}")
    print(f"Endpoints found: {len(results)}")
    
    # Save results if requested
    if args.output and results:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to: {args.output}")
    
    print("Scan completed!")

if __name__ == "__main__":
    main()