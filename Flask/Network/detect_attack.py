import json
import numpy as np
#from Network.network_rate import get_network_data
from Network.statistical_methods import get_detailed_process_info
from Network.statistical_methods import get_process_info_by_pid

def get_network_data():
    network_data = []
    timestamps = []

    try:
        with open("network_data.json", 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())  # Use strip to remove potential trailing whitespace
                    timestamps.append(data["timestamp"])
                    network_data.append(data["network"])
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")
                    continue
    except FileNotFoundError:
        print("File not found. Ensure 'network_data.json' exists.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
    if not network_data:
        print("No valid network data available.")
        return {}
    return network_data
#Establish baseline behavior
def establish_baseline(duration=3600):  # 1 hour by default
    #baseline_data = collect_data(duration)
    baseline_data = get_network_data()
    baseline_stats = calculate_baseline_stats(baseline_data)
    save_baseline(baseline_stats)

def calculate_baseline_stats(data):
    # Initialize the structure
    baseline_stats = {}
    for interface in data[0].keys():
        if interface != 'connection_details':
            baseline_stats[interface] = {
                "bytes_sent_rate": [],
                "bytes_recv_rate": [],
                "packets_sent_rate": [],
                "packets_recv_rate": []
            }
            
            prev_stats = data[0][interface]
            for current_data in data[1:]:
                current_stats = current_data[interface]
                baseline_stats[interface]["bytes_sent_rate"].append(current_stats["bytes_sent"] - prev_stats["bytes_sent"])
                baseline_stats[interface]["bytes_recv_rate"].append(current_stats["bytes_recv"] - prev_stats["bytes_recv"])
                baseline_stats[interface]["packets_sent_rate"].append(current_stats["packets_sent"] - prev_stats["packets_sent"])
                baseline_stats[interface]["packets_recv_rate"].append(current_stats["packets_recv"] - prev_stats["packets_recv"])
                prev_stats = current_stats
    # Calculate mean and standard deviation
    
    for interface in baseline_stats:
        for metric in ['bytes_sent_rate', 'bytes_recv_rate', 'packets_sent_rate', 'packets_recv_rate']:
            baseline_stats[interface][metric] = {
                'mean': np.mean(baseline_stats[interface][metric]),
                'std': np.std(baseline_stats[interface][metric])
            }
    #print(baseline_stats) 
    return baseline_stats


def save_baseline(baseline_stats):
    with open('baseline_stats.json', 'w') as f:
        json.dump(baseline_stats, f)

def load_baseline():
    with open('baseline_stats.json', 'r') as f:
        return json.load(f)
    
    
#implement specific attack attack detection modules
def detect_ddos(data, baseline):
    # Check for abnormally high incoming traffic
    
    threshold = baseline['Wi-Fi']['bytes_recv_rate']['mean'] + 3 * baseline['Wi-Fi']['bytes_recv_rate']['std']
    return any(rate > threshold for rate in data['Wi-Fi']['bytes_recv_rate'])

def detect_data_exfiltration(data, baseline):
    # Check for abnormally high outgoing traffic
    threshold = baseline['Wi-Fi']['bytes_sent_rate']['mean'] + 3 * baseline['Wi-Fi']['bytes_sent_rate']['std']
    return any(rate > threshold for rate in data['Wi-Fi']['bytes_sent_rate'])

def detect_port_scanning(connection_data):
    # Check for many short-lived connections to different ports
    connections_per_ip = {}
    for conn in connection_data:
        ip = conn['remote_ip']
        if ip not in connections_per_ip:
            connections_per_ip[ip] = set()
        connections_per_ip[ip].add(conn['remote_port'])
    return any(len(ports) > 100 for ports in connections_per_ip.values())

def detect_brute_force(connection_data):
    # Check for many failed connection attempts
    failed_attempts = sum(1 for conn in connection_data if conn['status'] == 'CLOSE_WAIT')
    return failed_attempts > 100  # Adjust threshold as needed





def analyze_connection_patterns(connection_data):
    connection_counts = {}
    suspicious_connections = []
    for conn in connection_data:
        key = (conn['remote_ip'], conn['remote_port'])
        connection_counts[key] = connection_counts.get(key, 0) + 1
        
        if connection_counts[key] > 100:  # Adjust threshold as needed
            suspicious_connections.append({
                'remote_ip': conn['remote_ip'],
                'remote_port': conn['remote_port'],
                'pid': conn['pid'],
                'status': conn['status'],
                'count': connection_counts[key]
            })
    
    return suspicious_connections

#correlation engine
def correlate_events(network_data, connection_data):
    potential_attacks = []
    establish_baseline()
    baseline = load_baseline()
    
    if detect_ddos(network_data, baseline):
        potential_attacks.append(("DDoS", "High incoming traffic detected"))
    
    if detect_data_exfiltration(network_data, baseline):
        potential_attacks.append(("Data Exfiltration", "High outgoing traffic detected"))
    
    if detect_port_scanning(connection_data):
        potential_attacks.append(("Port Scanning", "Multiple connections to different ports detected"))
    
    if detect_brute_force(connection_data):
        potential_attacks.append(("Brute Force", "Multiple failed connection attempts detected"))
    
    seen_pids = set()
    suspicious_connections = analyze_connection_patterns(connection_data)
    if suspicious_connections:
        detailed_suspicious_connections = []
        for conn in suspicious_connections:
            if conn['status'] == 'ESTABLISHED' or conn['pid'] != 0:
                pid = conn['pid']
                if pid not in seen_pids:
                    detailed_info = get_detailed_process_info(pid)
                    if detailed_info:
                        conn['process_info'] = detailed_info
                        detailed_suspicious_connections.append(conn)
                        seen_pids.add(pid)
            
        potential_attacks.append(("Suspicious Connections", f"Unusual connection patterns: {detailed_suspicious_connections}"))
    return potential_attacks