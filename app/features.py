
import pandas as pd
import numpy as np
import math
from collections import Counter

def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy

def extract_features(df):
    """
    Extracts features from the DataFrame containing DNS query data.
    """
    # Essential features
    df['query_length'] = df['query'].apply(len)
    df['entropy'] = df['query'].apply(entropy)
    df['subdomain_count'] = df['query'].apply(lambda x: x.count('.'))
    df['max_label_len'] = df['query'].apply(lambda x: max([len(label) for label in x.split('.')]) if '.' in x else len(x))
    
    # Numerical ratio 
    def ratio_numerical(string):
        if not string: return 0
        numerical = sum(c.isdigit() for c in string)
        return numerical / len(string)
        
    df['ratio_numerical'] = df['query'].apply(ratio_numerical)
    
    return df
