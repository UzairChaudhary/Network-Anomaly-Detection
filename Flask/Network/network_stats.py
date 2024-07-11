# Function to get network statistics
import psutil
import time
from scapy.all import sniff, IP


def get_network_stats():
    net_io = psutil.net_io_counters(pernic=True)
    network_stats = {}

    for interface, stats in net_io.items():
        network_stats[interface] = {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout
        }
    
    return network_stats


def capture_packet_info(packet):
    if IP in packet:
        return {
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": packet[IP].proto,
            "len": len(packet),
            "timestamp": time.time()
        }
    return None


def get_network_stats_with_packets():
    net_io = psutil.net_io_counters(pernic=True)
    network_stats = {}
    for interface, stats in net_io.items():
        network_stats[interface] = {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout
        }
    
    # Capture packets for a short duration
    packets = sniff(timeout=1, prn=capture_packet_info, store=False)
    network_stats["packet_details"] = [p for p in packets if p is not None]
    
    return network_stats


def get_network_stats_with_connections():
    net_io = psutil.net_io_counters(pernic=True)
    network_stats = {}
    for interface, stats in net_io.items():
        network_stats[interface] = {
            "bytes_sent": stats.bytes_sent,
            "bytes_recv": stats.bytes_recv,
            "packets_sent": stats.packets_sent,
            "packets_recv": stats.packets_recv,
            "errin": stats.errin,
            "errout": stats.errout,
            "dropin": stats.dropin,
            "dropout": stats.dropout
        }
    
    # Get current network connections
    connections = psutil.net_connections()
    connection_details = []
    for conn in connections:
        if conn.laddr and conn.raddr:
            connection_details.append({
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "remote_ip": conn.raddr.ip,
                "remote_port": conn.raddr.port,
                "status": conn.status,
                "pid": conn.pid
            })
    
    network_stats["connection_details"] = connection_details
    
    return network_stats



#Enhanced Data collection
def collect_enhanced_data(duration=300, interval=1):
    start_time = time.time()
    enhanced_data = []
    while time.time() - start_time < duration:
        network_stats = get_network_stats_with_connections()
        system_stats = get_system_stats()
        enhanced_data.append({
            "timestamp": time.time(),
            "network": network_stats,
            "system": system_stats
        })
        time.sleep(interval)
    return enhanced_data

def get_system_stats():
    return {
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_io": psutil.disk_io_counters(),
        "open_files": len(psutil.Process().open_files()),
        "connections": len(psutil.net_connections())
    }