"""Convert PCAP data to json format for AWS Route53 logs"""

import json
import time
import random
from ingestion import parse_pcap_to_df

def generate_aws_logs(pcap_path, output_json):
    df = parse_pcap_to_df(pcap_path)

    if df.empty:
        print(f"Empty pcap file: {pcap_path}")
        return
    
    with open(output_json, 'w') as f:
        for _, row in df.iterrows():
            log_entry = {
                "version": "1.0",
                "account_id": "123456789012",
                "region": "us-east-1",
                "vpc_id": "vpc-12345678",
                "query_timestamp": row["timestamp"],
                "query": row["query"],
                "query_type": "A",
                "query_class": "IN",
                "rcode": "NOERROR",
                "answers": [],
                "srcaddr": "10.0.1.52",
                "srcport": 5353,
                "transport": "UDP",
                "srcids": {
                    "instance": "i-0123456789abcdef0"
                }
            }
            f.write(json.dumps(log_entry) + "\n")
    print(f"Generated {len(df)} logs to {output_json}")

generate_aws_logs("../../normal/normal_00000_20230805150331.pcap", "../../normal_logs.json")