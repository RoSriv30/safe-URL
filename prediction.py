# Load Libraries
import numpy as np
from pandas import read_csv
import pandas as pd
from pandas.plotting import scatter_matrix
from matplotlib import pyplot
from sklearn.model_selection import train_test_split
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.naive_bayes import GaussianNB
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
import pickle


# Load Dataset
url = "features.csv"
names = ['target', 'bodyLength', 'bscr', 'dse', 'dsr', 'entropy', 'hasHttp', 'hasHttps', 'has_ip', 'numDigits',
         'numImages', 'numLinks', 'numParams', 'numTitles', 'num_%20', 'num_@', 'sbr', 'scriptLength',
         'specialChars', 'sscr', 'urlIsLive', 'urlLength']
dataset = read_csv(url, names=names)


...
# Split-out validation dataset
array = dataset.values
X = array[:, 1:]
Y = array[:, 0:1]
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=.2, random_state=1)


...
# Create a Gaussian Classifier
clf = RandomForestClassifier(n_estimators=100)

# Train the model using the training sets y_pred = clf.predict(X_test)
clf.fit(X_train, Y_train.ravel())


# Saving model to current directory
# Pickle serializes objects so they can be saved to a file, and loaded in a program again later on.
# pickle.dump(clf, open('model.pkl', 'wb'))


Y_pred = clf.predict(X_test)
print("Accuracy:", metrics.accuracy_score(Y_test, Y_pred))
testArr = [1050,0.3542857143,1938,8287,-4.001514249,1,0,0,62,0,0,0,0,0,0,1,1050,372,2.822580645,0,192]
# print(clf.predict_proba([testArr]))
# print(clf.predict([testArr]))


...
# Loading model to compare the results
model = pickle.load(open('model.pkl', 'rb'))
print(model.predict([testArr]))




