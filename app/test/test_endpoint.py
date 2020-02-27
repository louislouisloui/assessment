import requests

def test_request():
    url = "http://127.0.0.1:5000/api/classify"
    payload = "{\n    \"raw_user_agent\": \"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10\"\n}"
    headers = {
    'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data = payload)
    assert response.status_code == 200

