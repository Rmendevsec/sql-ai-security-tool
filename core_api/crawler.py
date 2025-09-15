import requests

URL = input("Enter the URL to crawl: ")
resp = requests.get(URL)
print("Status code", resp.status_code)
print("\nResponse content: ")
print(resp.text)