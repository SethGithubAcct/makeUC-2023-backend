from flask import Flask, request
from google.cloud import secretmanager_v1 as secmgr
import openai
import json

# setup
app = Flask(__name__)
client = secmgr.SecretManagerServiceClient()
model = "gpt-4" # change me to change GPT model
system_prompt = """
You are a code vulnerability scanning AI. You are to analyze submitted code and check if there are vulnerabilities.
If a vulnerability is found, call the report_vulnerability function and fill out the required arguments accordingly.
Your response should be in JSON format.
"""
functions = [
    {
        "name": "report_vulnerability",
        "description": "Convert vulnerability info into JSON format.",
        "parameters": {
            "type": "object",
            "properties": {
                "vulnerability_type": {
                    "type": "string",
                    "description": "The type of vulnerability found, e.g. Buffer Overflow"
                },
                "severity": {
                    "type": "int",
                    "description": "A number between 1 and 10 indicating the severity of the vulnerability, with 10 being the most severe"
                },
                "mitigation_recommendation": {
                    "type": "string",
                    "description": "An explanation for the user on how they could fix the vulnerability in their code"
                }
            },
            "required": ["vulnerability_type", "severity", "mitigation_recommendation"]
        }
    }
]

# GPT-4 should call this function, which will structure its output into JSON format
def report_vulnerability(vulnerability_type, severity, mitigation_recommendation):
    return json.dumps({
        'vulnerability_type': vulnerability_type,
        'severity': severity,
        'mitigation_recommendation': mitigation_recommendation
    })

# get OpenAI key from secret manager
api_secret = client.access_secret_version(
    request=secmgr.AccessSecretVersionRequest(
        name='projects/makeuc-2023/secrets/openai-api-key/versions/latest'
    )
)
api_key = api_secret.payload.data.decode('utf-8')
openai.api_key = api_key

@app.route("/analyze", methods=['POST'])
def analyze(request):
    response = openai.ChatCompletion.create(
        model=model,
        messages=[
            {'role': "system", 'content': system_prompt},
            {'role': "user", 'content': request.data}
        ],
        functions=functions,
        function_call="report_vulnerability"
    )
    return json.dumps(response.choices[0].message)

if __name__ == "__main__":
    app.run()