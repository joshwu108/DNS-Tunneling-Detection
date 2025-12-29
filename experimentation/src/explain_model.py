import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt

print("-----Reading data-----")
df = pd.read_csv("../../processed_dataset.csv")
clf = joblib.load("../../random_forest_model.pkl")

print("-----Explaining model-----")
feature_cols = ['query_length', 'entropy', 'subdomain_count', 'max_label_len', 'ratio_numerical']
X = df[feature_cols]
explainer = shap.TreeExplainer(clf)
benign_sample = X[df['label'] == 0].sample(n=100, random_state=42)
tunnel_sample = X[df['label'] == 1].sample(n=100, random_state=42)
X_sample = pd.concat([benign_sample, tunnel_sample], ignore_index=True)

print("-----Calculating SHAP VAlues-----")
shap_values = explainer.shap_values(X_sample)

print("-----Visualizing SHAP Values-----")
plt.title("Feature importance in DNS Tunneling Detection")

shap_values_2d = shap_values[1].reshape(-1, 5)
print(shap_values_2d.shape)
print(X_sample.shape)
shap.summary_plot(shap_values_2d, X_sample, plot_type="bar", show=False)
plt.tight_layout()
plt.savefig("../../feat_importance.png")

plt.figure()
shap.summary_plot(shap_values, X_sample, show=False)
plt.tight_layout()
plt.savefig("../../shap_besswarm.png")

