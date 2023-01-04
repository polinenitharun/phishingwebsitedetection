import data as d
training_data,testing_data,training_label,testing_label=d.prepareData()

#DECISION TREE ALGORITHM FOR PHISHING WEBSITE DETECTION
from sklearn.tree import DecisionTreeClassifier
DTmodel = DecisionTreeClassifier(random_state=0)
DTmodel.fit(training_data,training_label)

predicted_label = DTmodel.predict(testing_data)

# CONFUSION MATRIX AND ACCURACY

from sklearn.metrics import confusion_matrix,accuracy_score
c_matrix = confusion_matrix(testing_label,predicted_label)

accuracy_score=accuracy_score(testing_label,predicted_label)*100
import pickle
file_name = "SAVfiles/DecisionTree.sav"
pickle.dump(DTmodel,open(file_name,'wb'))