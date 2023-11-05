from flask import Flask, request
from flask_cors import CORS, cross_origin
from google.cloud import secretmanager_v1 as secmgr
import openai
import json

# setup
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
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
def analyze(request):
    messages = [
        {'role': "system", 'content': system_prompt},
        {'role': "user", 'content': f"Analyze the following {request.data.language} code: {request.data.code}"}
    ] 
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        functions=functions,
        function_call="report_vulnerability"
    )
    response_message = response["choices"][0]["message"]
    if response_message.get("function_call"):
        available_functions = {
            "report_vulnerability": report_vulnerability
        }
        function_name = response_message["function_call"]["name"]
        called_function = available_functions[function_name]
        function_args = json.loads(response_message["function_call"]["arguments"])
        function_response = called_function(
            vulnerability_type=function_args.get("vulnerability_type"),
            severity=function_args.get("severity"),
            mitigation_recommendation=function_args.get("mitigation_recommendation")
        )
        messages.append(response_message)
        messages.append(
            {
                "role": "function",
                "name": function_name,
                "content": function_response
            }
        )
        final_response = openai.ChatCompletion.create(
            model=model,
            messages=messages
        )
        return final_response

if __name__ == "__main__":
    app.run()