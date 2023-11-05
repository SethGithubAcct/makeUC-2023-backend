#parses

from flask import Flask, request, render_template

app = Flask(__name__)
@app.route('/', methods=['post'])



def send_to_gpt4():
    if (request.method=='post'):
        #send data
       return 
#this was used to test the code
    return render_template('test.html')
    

    

if __name__=='__main__':
    app.run() 
    
