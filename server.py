from flask import Flask
from google.cloud import secretmanager_v1 as secmgr
import openai
import requests
import json

# setup
app = Flask(__name__)
client = secmgr.SecretManagerServiceClient()

# get OpenAI key from secret manager
api_secret = client.access_secret_version(
    request=secmgr.AccessSecretVersionRequest(
        name='projects/makeuc-2023/secrets/openai-api-key/versions/latest'
    )
)
api_key = api_secret.payload.data

@app.route("/analyze")
def analyze():
    return json.dumps({'api-key': api_key.decode('utf-8')})

app.run()