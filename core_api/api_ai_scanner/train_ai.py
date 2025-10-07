import json
import random
import pickle
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

class APIEndpointTrainer:
    def __init__(self):
        # Free sentence transformer model
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.endpoints = []
        self.descriptions = []
        self.embeddings = None
        
    def create_training_data(self):
        """Create training data from common API patterns"""
        print("Creating training data...")
        
        # Common API endpoints and their descriptions
        endpoint_patterns = [
            # Authentication endpoints
            {'endpoint': '/api/v1/auth/login', 'description': 'user login authentication'},
            {'endpoint': '/api/v1/auth/register', 'description': 'user registration signup'},
            {'endpoint': '/api/v1/auth/logout', 'description': 'user logout session'},
            {'endpoint': '/api/v1/auth/token', 'description': 'authentication token'},
            {'endpoint': '/api/v1/auth/refresh', 'description': 'refresh token'},
            
            # User management
            {'endpoint': '/api/v1/users', 'description': 'user management data'},
            {'endpoint': '/api/v1/users/{id}', 'description': 'get user by id'},
            {'endpoint': '/api/v1/users/profile', 'description': 'user profile information'},
            {'endpoint': '/api/v1/users/me', 'description': 'current user data'},
            
            # File operations
            {'endpoint': '/api/v1/files/upload', 'description': 'file upload endpoint'},
            {'endpoint': '/api/v1/files/download', 'description': 'file download'},
            {'endpoint': '/api/v1/files/{id}', 'description': 'get file by id'},
            {'endpoint': '/api/v1/files', 'description': 'file management'},
            
            # Admin endpoints
            {'endpoint': '/api/v1/admin/users', 'description': 'admin user management'},
            {'endpoint': '/api/v1/admin/dashboard', 'description': 'admin dashboard'},
            {'endpoint': '/api/v1/admin/settings', 'description': 'admin settings'},
            {'endpoint': '/admin', 'description': 'administrative panel'},
            
            # Product endpoints
            {'endpoint': '/api/v1/products', 'description': 'product catalog'},
            {'endpoint': '/api/v1/products/search', 'description': 'search products'},
            {'endpoint': '/api/v1/products/{id}', 'description': 'get product by id'},
            
            # Order endpoints
            {'endpoint': '/api/v1/orders', 'description': 'order management'},
            {'endpoint': '/api/v1/orders/{id}', 'description': 'get order by id'},
            {'endpoint': '/api/v1/orders/create', 'description': 'create new order'},
            
            # Search endpoints
            {'endpoint': '/api/v1/search', 'description': 'search functionality'},
            {'endpoint': '/api/v1/search/users', 'description': 'search users'},
            {'endpoint': '/api/v1/search/products', 'description': 'search products'},
            
            # Common API patterns from your wordlist
            {'endpoint': '/api', 'description': 'api base endpoint'},
            {'endpoint': '/api/v1', 'description': 'api version 1'},
            {'endpoint': '/api/v2', 'description': 'api version 2'},
            {'endpoint': '/graphql', 'description': 'graphql endpoint'},
            {'endpoint': '/rest', 'description': 'rest api'},
            
            # Authentication variations
            {'endpoint': '/login', 'description': 'user login'},
            {'endpoint': '/signin', 'description': 'user signin'},
            {'endpoint': '/register', 'description': 'user registration'},
            {'endpoint': '/signup', 'description': 'user signup'},
            {'endpoint': '/oauth', 'description': 'oauth authentication'},
            
            # File variations
            {'endpoint': '/upload', 'description': 'file upload'},
            {'endpoint': '/download', 'description': 'file download'},
            {'endpoint': '/files', 'description': 'file management'},
            {'endpoint': '/documents', 'description': 'document management'},
            
            # Admin variations
            {'endpoint': '/administrator', 'description': 'administrator access'},
            {'endpoint': '/manager', 'description': 'management panel'},
            {'endpoint': '/admin/login', 'description': 'admin login'},
            
            # Additional common endpoints
            {'endpoint': '/health', 'description': 'health check'},
            {'endpoint': '/status', 'description': 'system status'},
            {'endpoint': '/metrics', 'description': 'system metrics'},
            {'endpoint': '/config', 'description': 'configuration'},
            {'endpoint': '/settings', 'description': 'application settings'},
        ]
        
        # Generate variations for each endpoint
        training_data = []
        variations = {
            'login': ['login', 'signin', 'authentication', 'user access', 'session start'],
            'register': ['register', 'signup', 'create account', 'new user', 'registration'],
            'users': ['users', 'user management', 'user data', 'user accounts', 'user information'],
            'files': ['files', 'file management', 'documents', 'file storage', 'file system'],
            'upload': ['upload', 'file upload', 'add files', 'post files', 'upload documents'],
            'admin': ['admin', 'administrator', 'management', 'admin panel', 'system admin'],
            'products': ['products', 'product catalog', 'items', 'merchandise', 'goods'],
            'search': ['search', 'find', 'lookup', 'query', 'search functionality'],
            'orders': ['orders', 'purchases', 'transactions', 'sales', 'order management']
        }
        
        for pattern in endpoint_patterns:
            # Add the main pattern
            training_data.append({
                'input': pattern['description'],
                'output': pattern['endpoint']
            })
            
            # Generate variations
            endpoint = pattern['endpoint']
            for key, words in variations.items():
                if key in endpoint:
                    for word in words[:2]:  # Take first 2 variations
                        if word != pattern['description']:
                            training_data.append({
                                'input': word,
                                'output': endpoint
                            })
        
        print(f"Created {len(training_data)} training examples")
        return training_data
    
    def train(self, training_data):
        """Train the AI model"""
        print("Training AI model...")
        
        # Prepare data
        for item in training_data:
            self.endpoints.append(item['output'])
            self.descriptions.append(item['input'])
        
        # Create embeddings
        print("Creating embeddings...")
        self.embeddings = self.model.encode(self.descriptions)
        
        # Save the model
        model_data = {
            'endpoints': self.endpoints,
            'descriptions': self.descriptions,
            'embeddings': self.embeddings
        }
        
        with open('api_ai_model.pkl', 'wb') as f:
            pickle.dump(model_data, f)
        
        print("Model trained and saved as 'api_ai_model.pkl'")
        return model_data
    
    def test_model(self, test_queries=None):
        """Test the trained model"""
        if test_queries is None:
            test_queries = [
                "user login",
                "file upload", 
                "admin panel",
                "search products",
                "user registration"
            ]
        
        print("\nTesting AI model:")
        print("=" * 50)
        
        for query in test_queries:
            results = self.predict(query, top_k=3)
            print(f"\nQuery: '{query}'")
            for i, result in enumerate(results, 1):
                print(f"  {i}. {result['endpoint']} (score: {result['similarity']:.3f})")

    def predict(self, user_input, top_k=5):
        """Predict API endpoints based on user input"""
        if self.embeddings is None:
            raise ValueError("Model not trained yet")
        
        # Encode user input
        input_embedding = self.model.encode([user_input])
        
        # Calculate similarity
        similarities = cosine_similarity(input_embedding, self.embeddings)[0]
        
        # Get top matches
        top_indices = np.argsort(similarities)[-top_k:][::-1]
        
        results = []
        for idx in top_indices:
            if similarities[idx] > 0.1:  # Lower threshold for more results
                results.append({
                    'endpoint': self.endpoints[idx],
                    'similarity': float(similarities[idx]),
                    'description': self.descriptions[idx]
                })
        
        return results

def main():
    """Main training function"""
    print("API Endpoint AI Trainer")
    print("=" * 50)
    
    # Create trainer
    trainer = APIEndpointTrainer()
    
    # Create training data
    training_data = trainer.create_training_data()
    
    # Save training data for reference
    with open('training_data.json', 'w') as f:
        json.dump(training_data, f, indent=2)
    print("Training data saved to 'training_data.json'")
    
    # Train the model
    trainer.train(training_data)
    
    # Test the model
    trainer.test_model()
    
    print("\n" + "=" * 50)
    print("Training completed!")
    print("You can now use the AI model with your scanner")

if __name__ == "__main__":
    main()