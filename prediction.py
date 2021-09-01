import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pickle



df = pd.read_csv('phishing.csv')
X = df.drop(['class', 'Index'], axis=1)
Y = df['class']
Y = pd.DataFrame(Y)
# train_X, test_X, train_Y, test_Y = train_test_split(X, Y, test_size=0.3, random_state=2)
rfc=RandomForestClassifier()
model_4=rfc.fit(X, Y)
# rfc_predict=model_4.predict(test_X)
pickle.dump(model_4, open('model.pkl', 'wb'))
