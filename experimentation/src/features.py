import math
from collections import Counter

def calculate_entropy(text):
    if not text:
        return 0.0
    
    entropy = 0.0
    total_len = len(text)
    for count in Counter(text).values():
        p = count / total_len
        entropy -= p * math.log2(p)
    return entropy

def extract_features(df):
    if df.empty:
        return df
    df['query_length'] = df['query'].apply(len)
    df['entropy'] = df['query'].apply(calculate_entropy)
    df['subdomain_count'] = df['query'].apply(lambda x: x.count('.'))
    df['max_label_len'] = df['query'].apply(lambda x: max([len(l) for l in x.split('.')]) if x else 0)
    df['numerical_chars'] = df['query'].apply(lambda x: sum(c.isdigit() for c in x))
    df['ratio_numerical'] = df['numerical_chars'] / df['query_length']
    return df
