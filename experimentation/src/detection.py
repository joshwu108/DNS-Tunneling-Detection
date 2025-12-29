def heuristic_check(row):
    if row['entropy'] > 4.5 and row['query_length'] > 50:
        return "HIGH_CONFIDENCE_TUNNEL"
    
    if row['ratio_numerical'] > 0.4:
        return "SUSPICIOUS_DGA"

    if row['subdomain_count'] > 5:
        return "SUSPICIOUS_DEPTH"
    
    return "BENIGN"
