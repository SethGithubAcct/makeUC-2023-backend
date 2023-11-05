from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
from google.cloud import secretmanager_v1 as secmgr
import openai
import json

# setup
app = Flask(__name__)
cors = CORS(app, origins="*", methods="POST")
app.config['CORS_HEADERS'] = 'Content-Type'
client = secmgr.SecretManagerServiceClient()
model = "gpt-4" # change me to change GPT model
system_prompt = """
You are a code vulnerability scanning AI. You are to analyze submitted code and check if there are vulnerabilities.
If vulnerabilites are found, list each of them one by one (separated by newlines), explaining the vulnerability as well as providing a solution.
"""

# get OpenAI key from secret manager
api_secret = client.access_secret_version(
    request=secmgr.AccessSecretVersionRequest(
        name='projects/makeuc-2023/secrets/openai-api-key/versions/latest'
    )
)
api_key = api_secret.payload.data.decode('utf-8')
openai.api_key = api_key

# GPT-4 should call this function, which will structure its output into JSON format
def report_vulnerability(vulnerability_type, severity, mitigation_recommendation):
    return json.dumps({
        'vulnerability_type': vulnerability_type,
        'severity': severity,
        'mitigation_recommendation': mitigation_recommendation
    })

@app.route("/analyze", methods=['POST'])
@cross_origin()
def analyze():
    data_json = json.loads(request.data.decode('utf-8'))
    messages = [
        {'role': "system", 'content': system_prompt},
        {'role': "user", 'content': f"Analyze the following {data_json['language']} code: {data_json['code']}"}
    ] 
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
    )
    return response.choices[0].message.content

if __name__ == "__main__":
    app.run()