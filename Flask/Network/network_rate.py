import json

def get_network_data():
    network_data = []
    timestamps = []

    try:
        with open("new_network_data.json", 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())  # Use strip to remove potential trailing whitespace
                    timestamps.append(data["timestamp"])
                    network_data.append(data["network"])
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")
                    continue
    except FileNotFoundError:
        print("File not found. Ensure 'new_network_data.json' exists.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
    if not network_data:
        print("No valid network data available.")
        return {}
    return network_data

def calculate_network_rates():
    network_data = []
    timestamps = []

    try:
        with open("new_network_data.json", 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())  # Use strip to remove potential trailing whitespace
                    timestamps.append(data["timestamp"])
                    network_data.append(data["network"])
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")
                    continue
    except FileNotFoundError:
        print("File not found. Ensure 'new_network_data.json' exists.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
    if not network_data:
        print("No valid network data available.")
        return {}
    
    network_rates = {}
    for interface in network_data[0].keys():
        network_rates[interface] = {
            "bytes_sent_rate": [],
            "bytes_recv_rate": [],
            "packets_sent_rate": [],
            "packets_recv_rate": []
        }
        
        prev_stats = network_data[0][interface]
        
        for current_data in network_data[1:]:
            current_stats = current_data[interface]
            network_rates[interface]["bytes_sent_rate"].append(current_stats["bytes_sent"] - prev_stats["bytes_sent"])
            network_rates[interface]["bytes_recv_rate"].append(current_stats["bytes_recv"] - prev_stats["bytes_recv"])
            network_rates[interface]["packets_sent_rate"].append(current_stats["packets_sent"] - prev_stats["packets_sent"])
            network_rates[interface]["packets_recv_rate"].append(current_stats["packets_recv"] - prev_stats["packets_recv"])
            prev_stats = current_stats
    
    return network_rates


def calculate_network_rates_and_packets():
    network_rates = {}
    packet_details = []
    
    network_data = []
    timestamps = []

    try:
        with open("new_network_data.json", 'r') as file:
            for line in file:
                try:
                    data = json.loads(line.strip())  # Use strip to remove potential trailing whitespace
                    timestamps.append(data["timestamp"])
                    network_data.append(data["network"])
                except json.JSONDecodeError:
                    print(f"Skipping invalid JSON line: {line}")
                    continue
    except FileNotFoundError:
        print("File not found. Ensure 'new_network_data.json' exists.")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
    if not network_data:
        print("No valid network data available.")
        return {}


    for interface in network_data[0]['network'].keys():
        if interface != 'packet_details':
            network_rates[interface] = {
                "bytes_sent_rate": [],
                "bytes_recv_rate": [],
                "packets_sent_rate": [],
                "packets_recv_rate": []
            }
            
            prev_stats = network_data[0]['network'][interface]
            for current_data in network_data[1:]:
                current_stats = current_data['network'][interface]
                network_rates[interface]["bytes_sent_rate"].append(current_stats["bytes_sent"] - prev_stats["bytes_sent"])
                network_rates[interface]["bytes_recv_rate"].append(current_stats["bytes_recv"] - prev_stats["bytes_recv"])
                network_rates[interface]["packets_sent_rate"].append(current_stats["packets_sent"] - prev_stats["packets_sent"])
                network_rates[interface]["packets_recv_rate"].append(current_stats["packets_recv"] - prev_stats["packets_recv"])
                prev_stats = current_stats
    
    packet_details = [data['network']['packet_details'] for data in network_data]
    
    return network_rates, packet_details


def calculate_network_rates_and_connections():
    network_rates = {}
    connection_details = []
    network_data = get_network_data()
    for interface in network_data[0].keys():
        if interface != 'connection_details':
            network_rates[interface] = {
                "bytes_sent_rate": [],
                "bytes_recv_rate": [],
                "packets_sent_rate": [],
                "packets_recv_rate": []
            }
            
            prev_stats = network_data[0][interface]
            for current_data in network_data[1:]:
                current_stats = current_data[interface]
                network_rates[interface]["bytes_sent_rate"].append(current_stats["bytes_sent"] - prev_stats["bytes_sent"])
                network_rates[interface]["bytes_recv_rate"].append(current_stats["bytes_recv"] - prev_stats["bytes_recv"])
                network_rates[interface]["packets_sent_rate"].append(current_stats["packets_sent"] - prev_stats["packets_sent"])
                network_rates[interface]["packets_recv_rate"].append(current_stats["packets_recv"] - prev_stats["packets_recv"])
                prev_stats = current_stats
    
    connection_details = [data['connection_details'] for data in network_data]
    
    return network_rates, connection_details