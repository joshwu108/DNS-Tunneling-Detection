import pandas as pd
import glob
import os
from ingestion import parse_pcap_to_df
from features import extract_features

# Paths
NORMAL_DIR = "../../normal"
TUNNEL_DIR = "../../tunnel"
OUTPUT_CSV = "../../processed_dataset.csv"

def process_and_label(directory, label):
    all_dfs = []
    files = glob.glob(os.path.join(directory, "**/*.pcap"), recursive=True)
    for file in files:
        print(f"Processing {file}")
        df = parse_pcap_to_df(file)
        if not df.empty:
            df = extract_features(df)
            df['label'] = label
            all_dfs.append(df)
    if all_dfs:
        return pd.concat(all_dfs, ignore_index=True)
    else:
        return pd.DataFrame()

df_normal = process_and_label(NORMAL_DIR, label=0)
df_tunnel = process_and_label(TUNNEL_DIR, label=1)

full_dataset = pd.concat([df_normal, df_tunnel], ignore_index=True)
full_dataset.to_csv(OUTPUT_CSV, index=False)