import data as d
training_data,testing_data,training_label,testing_label=d.prepareData()
#SUPPORT VECTOR MACHINE MODEL
from sklearn.svm import SVC
svm = SVC(kernel='linear', C=1.0, random_state=12)
#MODEL FITTING
svm.fit(training_data,training_label)
predicted_label = svm.predict(testing_data)
#ACCURACY SCORE AND CONFUSION SCORE
from sklearn.metrics import confusion_matrix,accuracy_score
c_matrix = confusion_matrix(testing_label,predicted_label)
accuracy_score=accuracy_score(testing_label,predicted_label)*100
import pickle
file_name = "SAVfiles/SupportVectorMachine.sav"
pickle.dump(svm,open(file_name,'wb'))