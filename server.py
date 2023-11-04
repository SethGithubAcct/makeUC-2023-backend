from flask import Flask
import openai
import requests
import json

app = Flask(__name__)

@app.route("/analyze")
def analyze():
    return json.dumps({'hello': 'world'})

app.run()