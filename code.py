import requests

#URL with Render URL
API_URL = "https://blockifyurl.onrender.com/api/predict"

payload = {"url": "http://example.com"}
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

response = requests.post(API_URL, json=payload, headers=headers)

print(response.json())
