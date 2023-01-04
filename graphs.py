import Decisiontree
import RandomForest
import svm
import XGBclassifier
import matplotlib.pyplot as plt
import pandas as pd
legitimate_urls = pd.read_csv("dataset/legitimateurls.csv")
phishing_urls = pd.read_csv("dataset/phishingurls.csv")
def accuracy_graph():
    X_axis=['Decision_tree','Random_forest','SVM','XGBclassifier']
    Y_axis=[Decisiontree.accuracy_score,RandomForest.accuracy_score,svm.accuracy_score,XGBclassifier.accuracy_score]
    fig = plt.figure(figsize=(10,10)) 
    plt.bar(X_axis,Y_axis)
    plt.title("Accuracy Comparison of 4 Algorithms")
    plt.ylabel("Accuracy_score")
    fig.savefig('graphs/accuracygraph.jpg', dpi=150)
    plt.show()
accuracy_graph()

def dataset():    
    label = ["Legitimate_URL's","Phishing_URL's"]
    size = [len(legitimate_urls),len(phishing_urls)]
    fig = plt.figure(figsize =(10, 7))
    plt.pie(size, labels = label)
    fig.savefig('graphs/dataset.jpg',dpi=150)
    plt.show()
dataset()