import requests
import time

url = "http://localhost:5001/login"
print(f"Testing Rate Limit on {url}...")

try:
    for i in range(1, 16):
        response = requests.get(url)
        print(f"Request {i}: {response.status_code}")
        if response.status_code == 429:
            print("SUCCESS: Rate limit triggered (429 Too Many Requests)")
            break
        time.sleep(0.2)
except Exception as e:
    print(f"Error: {e}")
