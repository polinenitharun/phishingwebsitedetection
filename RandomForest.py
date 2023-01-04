import data as d
training_data,testing_data,training_label,testing_label=d.prepareData()

# RANDOM FORECT ALGORITHM

from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(training_data,training_label)
predicted_label = RFmodel.predict(testing_data)
#ACCURACY SCORE AND CONFUSION MATRIX
from sklearn.metrics import confusion_matrix,accuracy_score
cm2 = confusion_matrix(testing_label,predicted_label)
accuracy_score=accuracy_score(testing_label,predicted_label)*100
#SAVING THE MODEL DATA
import pickle
file_name = "SAVfiles/RandomForestModel.sav"
pickle.dump(RFmodel,open(file_name,'wb'))


