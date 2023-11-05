from flask import Flask
from google.cloud import secretmanager_v1 as secmgr
import openai
import requests
import json

# setup
app = Flask(__name__)
client = secmgr.SecretManagerServiceClient()
model = "gpt-3.5-turbo" # change me to change GPT model

# get OpenAI key from secret manager
api_secret = client.access_secret_version(
    request=secmgr.AccessSecretVersionRequest(
        name='projects/makeuc-2023/secrets/openai-api-key/versions/latest'
    )
)
api_key = api_secret.payload.data.decode('utf-8')
openai.api_key = api_key

@app.route("/analyze")
def analyze():
    response = openai.ChatCompletion.create(
        model=model,
        messages=[
            {'role': "system", 'content': "You are an AI that analyzes programs for security vulnerabilites."},
            {'role': "user", 'content': "What is a buffer overflow vulnerability?"}
        ]
    )
    return json.dumps(response.choices[0].message)

app.run()