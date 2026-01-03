import pandas as pd

"""File for random testing stuff"""

df = pd.read_csv("../../processed_dataset.csv")
print(df[['label']].value_counts())