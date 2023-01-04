import pandas as pd
def prepareData():
    # GETTING DATA FROM CSV FILES
    legitimate_urls = pd.read_csv("dataset/legitimateurls.csv")
    phishing_urls = pd.read_csv("dataset/phishingurls.csv")
    # MERGING LEGITIMATE AND PHISHING DATASETS
    urls = legitimate_urls.append(phishing_urls)
    #DROPPING UNREQUIRED DATA
    urls = urls.drop(urls.columns[[0,3,5]],axis=1)
    # SHUFFLING THE DATA
    urls = urls.sample(frac=1).reset_index(drop=True)
    # SEPERATING THE LABEL 
    urls_without_labels = urls.drop('label',axis=1)
    urls_without_labels.columns
    labels = urls['label']
    # TRAIN AND TEST DATA SPLIT
    import random
    random.seed(100)
    from sklearn.model_selection import train_test_split
    data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20, random_state=100)
    return data_train,data_test,labels_train,labels_test
    