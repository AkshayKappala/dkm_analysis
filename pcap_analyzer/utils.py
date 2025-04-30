import os
import sys
import numpy as np

# Define default configuration values
DEFAULT_CONFIG = {
    'var_folder': 'var',
    'time_interval': 1.0,
    'sample_rate': 1.0,
    'plot_type': 'all',
    'save_plots': True,
    'output_dir': 'output'
}

# Color styles for different datasets
COLORS = ['black', 'black', 'black', 'black', 'black', 'black']
STYLES = ['-', '--', '-.', ':', (0, (3, 1, 1, 1)), (0, (5, 1))]

def find_pcapng_files(directory):
    """Finds all .pcapng files in the specified directory."""
    pcap_files = []
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' not found.")
        return None
    for filename in os.listdir(directory):
        if filename.lower().endswith('.pcapng'):
            pcap_files.append(os.path.join(directory, filename))
    return pcap_files

def clean_filename(filename):
    """
    Cleans a filename for display by removing the pcapng extension
    and any file path information.
    """
    # Get just the filename without the path
    base_name = os.path.basename(filename)
    # Remove .pcapng extension if present
    if base_name.lower().endswith('.pcapng'):
        return base_name[:-7]  # Remove .pcapng (7 characters)
    # Otherwise just return the basename
    return base_name

def get_durations(file_data):
    """Get the duration of each pcap file."""
    durations = {}
    
    for metric_type in ['pps', 'rtt', 'throughput']:
        for filename, data in file_data.items():
            if metric_type in data and data[metric_type][0] is not None and len(data[metric_type][0]) > 0:
                times = data[metric_type][0]
                duration = times[-1] if len(times) > 0 else 0
                
                if filename not in durations or duration > durations[filename]:
                    durations[filename] = duration
    
    return durations

def ensure_dir_exists(directory):
    """Ensure that a directory exists, create it if it doesn't."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")
    return directory

def get_output_path(filename_prefix, output_dir):
    """Generate full output path for plots."""
    ensure_dir_exists(output_dir)
    return os.path.join(output_dir, f"{filename_prefix}.png")