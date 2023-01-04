import data as d
training_data,testing_data,training_label,testing_label=d.prepareData()
from xgboost import XGBClassifier
#XGMclassifier ALGORITHM 
xgb = XGBClassifier(learning_rate=0.4,max_depth=7)
xgb.fit(training_data,training_label)
predicted_label = xgb.predict(testing_data)
#ACCURACY SCORE AND CONFUSION MATRIX
from sklearn.metrics import confusion_matrix,accuracy_score
c_matrix = confusion_matrix(testing_label,predicted_label)
accuracy_score=accuracy_score(testing_label,predicted_label)*100
import pickle
file_name = "SAVfiles/XGBclassifier.sav"
pickle.dump(xgb,open(file_name,'wb'))