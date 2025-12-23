"""Simple file created to process the pcap files"""

from scapy.all import rdpcap, DNS, IP, UDP, DNSQR
import pandas as pandas

def parse_pcap_to_df(file_path):
    try:
        packets = rdcap(file_path)
    except FileNotFoundError:
        print(f"File not found at the path: {file_path}")
        return pd.DataFrame()

    data = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                #extract query information from the packets
                query_bytes = pkt[DNSQR].qname
                query = query_bytes.decode('utf-8').rstrip('.')
                qtype = pkt[DNSQR].qtype
                src_ip = pkt[IP].src if pkt.haslayer(IP) else FileNotFoundError
                timestamp = float(pkt.time)
                data.append({
                    'timestamp': timestamp,
                    'src_ip': src_ip,
                    'query': query,
                    'qtype': qtype,
                    'size': len(pkt)
                })
            except Exception as e:
                print(f"Error processing packet {pkt}: {e}")
                continue

    return pd.DataFrame(data)   
