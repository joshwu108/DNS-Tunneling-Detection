"""Simple file for checking if model works with AWS Route 53 logs""""

import json 
import pandas as pd
import joblib
from features import extract_features

clf = joblib.load("../../random_forest_model.pkl")

def scan_cloud_logs(log_file):
    print(f"Scanning cloud logs: {log_file}...")
    data = []
    with open(log_file, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                data.append({
                    'query': log_entry['query'],
                    'timestamp': log_entry['query_timestamp'],
                    'instance_id': log_entry['srcids']['instance']
                })
            except json.JSONDecodeError:
                print(f"Error parsing line: {line}")
                continue

    df = pd.DataFrame(data)
    df = extract_features(df)
    feature_cols = ['query_length', 'entropy', 'subdomain_count', 'max_label_len', 'ratio_numerical']
    X = df[feature_cols]
    df['is_malicious'] = clf.predict(X)

    alerts = df[df['is_malicious'] == 1]
    if not alerts.empty:
        print(f"Alarm: Found {len(alerts)} malicious queries")
    else:
        print("No threats found")

scan_cloud_logs("../../normal_logs.json")
    