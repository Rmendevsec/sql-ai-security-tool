import requests
import json
import time

# Define the target API endpoint (using a public API for demonstration)
API_URL = "http://crapi.apisec.ai/"

def test_api_get():
    """Test a simple GET request to retrieve data from the API."""
    try:
        response = requests.get(API_URL)
        print(f"GET Status Code: {response.status_code}")
        if response.status_code == 200:
            print("GET Request Successful. Sample Data:")
            print(json.dumps(response.json()[:2], indent=2))  # Print first two items
        else:
            print(f"GET Request Failed: {response.text}")
    except requests.RequestException as e:
        print(f"GET Request Error: {e}")

def test_api_post(payload):
    """Test a POST request to check input handling."""
    try:
        headers = {"Content-Type": "application/json"}
        response = requests.post(API_URL, json=payload, headers=headers)
        print(f"POST Status Code: {response.status_code}")
        if response.status_code == 201:
            print("POST Request Successful. Response:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"POST Request Failed: {response.text}")
    except requests.RequestException as e:
        print(f"POST Request Error: {e}")

def test_rate_limiting():
    """Test for rate limiting by sending multiple requests."""
    for i in range(5):
        response = requests.get(API_URL)
        print(f"Rate Limit Test {i+1} - Status Code: {response.status_code}")
        if "X-Rate-Limit" in response.headers:
            print(f"Rate Limit Info: {response.headers['X-Rate-Limit']}")
        time.sleep(1)  # Avoid overwhelming the server

def test_invalid_input():
    """Test API response to invalid input."""
    invalid_payload = {"title": "x" * 1000}  # Oversized input
    try:
        response = requests.post(API_URL, json=invalid_payload)
        print(f"Invalid Input Test - Status Code: {response.status_code}")
        print(f"Response: {response.text}")
    except requests.RequestException as e:
        print(f"Invalid Input Test Error: {e}")

if __name__ == "__main__":
    print("Starting API Tests...")
    # Test 1: Basic GET request
    print("\nTesting GET Request:")
    test_api_get()

    # Test 2: POST request with valid payload
    print("\nTesting POST Request:")
    valid_payload = {
        "title": "Test Post",
        "body": "This is a test post created via Python.",
        "userId": 1
    }
    test_api_post(valid_payload)

    # Test 3: Rate limiting test
    print("\nTesting Rate Limiting:")
    test_rate_limiting()

    # Test 4: Invalid input test
    print("\nTesting Invalid Input:")
    test_invalid_input()