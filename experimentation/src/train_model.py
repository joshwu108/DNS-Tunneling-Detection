import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import joblib

#read dataset
print("-----Reading data-----")
df = pd.read_csv("../../processed_dataset.csv")
feature_cols = ['query_length', 'entropy', 'subdomain_count', 'max_label_len', 'ratio_numerical']
X = df[feature_cols]
y = df['label']

print("-----Splitting data-----")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

print("-----Training model-----")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)

#Evaluate Model Performance
print("-----Model Performance-----")
print(classification_report(y_test, y_pred))
print(confusion_matrix(y_test, y_pred))

# save 
joblib.dump(clf, "../../random_forest_model.pkl")