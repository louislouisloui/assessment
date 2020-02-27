# Project organisation
The api code is located in the app directory.

The notebook walk through notebook reproduces the code and introduces every step.

The data is not tracked and the entire github data repo should be clone at the root of the project if one's want to reproduce it.

The package requirements are located in the file requirements.txt

# Installation
The api runs on python 3.6.10 and need the lib listed in the requirements.

# Launch API
At the root of the project run:
```python
python app/run.py
```
This will open a REST server on the default url: 127.0.0.1:5000

# Get a prediction
Post a POST query to the url 127.0.0.1:5000/api/classify.

Attach the agent in the body in json as follow;
```json
{
    "raw_user_agent":"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10"
}
```

This will return the answer as a json as follow:
```json
{
    "prediction": "benign"
}
```
The cURL entire command:
```curl
curl --location --request POST 'http://127.0.0.1:5000/api/classify' \
--header 'Content-Type: application/json' \
--data-raw '{
    "raw_user_agent": "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10"
}'
```
# Get bulk prediction
A second endpoint lets you get predictions in bulk. The user_agent must be sent as a json with the key being the unique identifier. Exemple:
```json
{
    "0": "Mozilla\\/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident\\/6.0)",
    "1": "Mozilla\\/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident\\/6.0)"
}

```
This endpoint makes it easier to get the predictions for the anomaly set. Here is the python code (also available in the main notebook):
```python
# Extract user-agents
with open('./aktaion/data/proxyData/exploitData/2014-01-02-neutrino-exploit-traffic.webgateway','rb') as e:
    exploit = e.readlines()
result = list()
for file in os.listdir('./aktaion/data/proxyData/exploitData'):
    with open('./aktaion/data/proxyData/exploitData/'+file,'rb') as e:
        exploit = e.readlines()
        result+=exploit
exploit_user_ag = [str(i).split('"')[11] for i in result]
# Format payload and query
body = pd.Series(exploit_user_ag).to_json()
url = "http://127.0.0.1:5000/api/classify_bulk"
payload = "{\n    \"raw_user_agent\": \"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.237 Safari/534.10\"\n}"
headers = {
'Content-Type': 'application/json'
}
# Send query
response = requests.request("POST", url, headers=headers, data = body)

# Result
print(response.text.encode('utf8'))
```

# Test
The API has one test which covers the prediction endpoint. It uses the python package pytest, and it can be triggered by running:
```python
pytest app/test
```