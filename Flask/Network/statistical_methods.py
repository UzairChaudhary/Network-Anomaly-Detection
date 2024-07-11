import numpy as np
import psutil
import datetime
# Function to calculate mean and std deviation
def calculate_mean_std(data):
    mean = np.mean(data)
    std = np.std(data)
    return mean, std

# Function to calculate Z-score with a check for zero std deviation
def calculate_z_scores(data, mean, std):
    if std == 0:
        return np.zeros_like(data)
    z_scores = (data - mean) / std
    return z_scores

# Function to detect anomalies
def detect_anomalies(data, z_scores, threshold):
    anomalies = np.where(np.abs(z_scores) > threshold)[0]
    return anomalies
# Function to get process information by PID
def get_process_info_by_pid(pid):
    
    if not isinstance(pid, int) or pid <= 0:
        print(f"Invalid PID: {pid}")
        return None
    try:
        proc = psutil.Process(pid)
        return {
            "pid": pid,
            "name": proc.name(),
            "username": proc.username(),
            "exe": proc.exe(),
            "status": proc.status()
            
        }
    except psutil.NoSuchProcess:
        return None
    except psutil.AccessDenied:
        return None
    except psutil.ZombieProcess:
        return None
    
    
    
def get_detailed_process_info(pid):
    try:
        process = psutil.Process(pid)
        return {
            'pid': pid,
            'name': process.name(),
            'exe': process.exe(),
            'cmdline': process.cmdline(),
            'username': process.username(),
            'cpu_percent': process.cpu_percent(),
            'memory_percent': process.memory_percent(),
            'status': process.status(),
            'create_time': datetime.fromtimestamp(process.create_time()).strftime("%Y-%m-%d %H:%M:%S"),
            'connections': [conn._asdict() for conn in process.connections()],
            'open_files': [file.path for file in process.open_files()],
            'num_threads': process.num_threads(),
            'parent': process.parent().pid if process.parent() else None,
        }
    except psutil.NoSuchProcess:
        return {'pid': pid, 'error': 'Process not found'}
    except psutil.AccessDenied:
        return {'pid': pid, 'error': 'Access denied'}
    except Exception as e:
        return {'pid': pid, 'error': str(e)}