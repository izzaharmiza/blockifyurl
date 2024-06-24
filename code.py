import requests

url = "http://127.0.0.1:5000/api/predict"

payload = {"url": "http://example.com"}
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

response = requests.post(url, json=payload, headers=headers)

print(response.json())
