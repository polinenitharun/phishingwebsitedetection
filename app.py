from flask import Flask,render_template,request
import Decisiontree
import RandomForest
import svm
import XGBclassifier
import Features
import pickle
app = Flask(__name__)

@app.route('/')
def input():
    return render_template("input.html")
    
@app.route('/',methods=['POST','GET'])
def inp():
    text = request.form['text']
    data=Features.getAttributess(text)
    RFmodel = pickle.load(open('SAVfiles/RandomForestModel.sav', 'rb'))
    DTmodel=pickle.load(open('SAVfiles/DecisionTree.sav','rb'))
    SVMmodel=pickle.load(open('SAVfiles/SupportVectorMachine.sav','rb'))
    XGBclassifier=pickle.load(open('SAVfiles/XGBclassifier.sav','rb'))
    predicted_value1 = RFmodel.predict(data)
    predicted_value2 = DTmodel.predict(data)
    predicted_value3 = SVMmodel.predict(data)
    predicted_value4 = XGBclassifier.predict(data)
    if predicted_value1 == 0 and predicted_value2 == 0 and predicted_value3 == 0 and predicted_value4 == 0:    
        error = "Legitimate_URL"
        return render_template("input.html",error=error)
    else:
        error = "Phishing_URL"
        return render_template("input.html",error=error)

if __name__ == "__main__":
    app.run(debug=True)