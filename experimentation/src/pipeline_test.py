import pandas as pd
from ingestion import parse_pcap_to_df
from features import extract_features
from detection import heuristic_check
import os

normal_pcap = "../../normal/normal_00000_20230805150331.pcap"
tunnel_pcap = "../../tunnel/dnscat2-cname.pcap"

print(f"processing normal traffic: {normal_pcap}")
df_normal = parse_pcap_to_df(normal_pcap)
if not df_normal.empty:
    df_normal = extract_features(df_normal)
    df_normal['detection'] = df_normal.apply(heuristic_check, axis=1)
    print(df_normal[['query', 'entropy', 'detection']].head(10))
else:
    print("empty normal pcap, nothing to process")

print(f"processing tunnel traffic: {tunnel_pcap}")
df_tunnel = parse_pcap_to_df(tunnel_pcap)
if not df_tunnel.empty:
    df_tunnel = extract_features(df_tunnel)
    df_tunnel['detection'] = df_tunnel.apply(heuristic_check, axis=1)
    print(df_tunnel[['query', 'entropy', 'detection']].head(10))
else:
    print("empty tunnel pcap")

