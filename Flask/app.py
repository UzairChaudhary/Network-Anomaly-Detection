from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import numpy as np
from sklearn.ensemble import IsolationForest
import time

from Network.network_stats import get_network_stats
from Network.network_stats import get_network_stats_with_packets
from Network.network_stats import get_network_stats_with_connections


from Network.statistical_methods import calculate_mean_std
from Network.statistical_methods import calculate_z_scores
from Network.statistical_methods import detect_anomalies
from Network.statistical_methods import get_process_info_by_pid

from Network.network_rate import calculate_network_rates
from Network.network_rate import calculate_network_rates_and_packets
from Network.network_rate import calculate_network_rates_and_connections


from Network.detect_attack import correlate_events

app = Flask(__name__)
CORS(app)


def isolation_forest_anomaly_detection(data, contamination=0.05):
    X = np.array(data).reshape(-1, 1)
    clf = IsolationForest(contamination=contamination, random_state=42)
    clf.fit(X)
    y_pred = clf.predict(X)
    anomalies = np.where(y_pred == -1)[0]
    return anomalies.tolist()

@app.route('/')
def Home():
    return "Anomaly Detection Homepage"

@app.route('/collect_data', methods=['POST'])
def collect_data():
    duration = request.json.get('duration', 300)  # Default to 5 min
    interval = request.json.get('interval', 1)   # Default to 1 second

    #network_data = []
    start_time = time.time()

    while time.time() - start_time < duration:
        data = {
            "timestamp": time.time(),
            #"network": get_network_stats()
            "network": get_network_stats_with_connections()
        }
        #network_data.append(data)
        
        with open("new_network_data.json", "a") as f:
            f.write(json.dumps(data) + "\n")
        
        time.sleep(interval)

    #return jsonify(network_data)

@app.route('/analyze', methods=['GET'])
def analyze():
    # data = request.json
    # method = data.get('method', 'z-score')
    # print(data)
    
    #collect_data()
    #network_rates = calculate_network_rates()
    network_rates, connection_details = calculate_network_rates_and_connections()
    results = {
        'z-score': {},
        'isolation-forest': {}
    }
    
    for method in ['z-score', 'isolation-forest']:
        for interface, rates in network_rates.items():
            interface_results = {}
            for rate_type in ['bytes_sent_rate', 'bytes_recv_rate', 'packets_sent_rate', 'packets_recv_rate']:
                if method == 'z-score':
                    #print(method)
                    mean, std = calculate_mean_std(rates[rate_type])
                    z_scores = calculate_z_scores(np.array(rates[rate_type]), mean, std)
                    anomalies = detect_anomalies(rates[rate_type], z_scores, 3).tolist()
                else:  # isolation forest
                    #print(method)
                    anomalies = isolation_forest_anomaly_detection(rates[rate_type])
                
                anomaly_info = []
                # use a set to track seen PIDs
                seen_pids = set()
                if len(anomalies) > 0:            
                    for idx in anomalies:
                        rate_value = rates[rate_type][idx]
                        relevant_connections = connection_details[idx]
                        # Filter connections and get process info
                        process_info = []
                        
                        for conn in relevant_connections:
                            if conn['status'] == 'ESTABLISHED' or conn['pid'] != 0:
                                pid = conn['pid']
                                if pid not in seen_pids:
                                    proc_info = get_process_info_by_pid(pid)
                                    if proc_info:
                                        process_info.append(proc_info)
                                        seen_pids.add(pid)
                        
                        anomaly_info.append({
                            "index": idx,
                            "rate_value": rate_value,
                            "process_info": process_info
                        })
                        
                #print(seen_pids)    
                                    
                interface_results[rate_type] = {
                    'data': rates[rate_type],
                    'anomalies': anomaly_info,
                
                    
                }
            results[method][interface] = interface_results
    
    return jsonify(results)



#detect attack type
@app.route('/detect', methods=['GET'])
def detect():
    #enhanced_data = collect_enhanced_data()
    network_rates, connection_details = calculate_network_rates_and_connections()
    
    potential_attacks = correlate_events(network_rates, connection_details[-1])
    
    
    results = {
        'potential_attacks': potential_attacks,
        'network_rates': network_rates,
        'connection_details': connection_details[-1]
    }
    
    return jsonify(results)


if __name__ == '__main__':
    app.run(debug=True)