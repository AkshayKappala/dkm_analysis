import os
import matplotlib.pyplot as plt
import numpy as np
import subprocess
import sys

# Define the directory containing the pcapng files
VAR_FOLDER = 'var'
# Define the time interval for calculating packets per second (in seconds)
TIME_INTERVAL = 1.0
# Sample rate for large files (1.0 = process all packets, 0.1 = process 10% of packets)
SAMPLE_RATE = 1.0

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

def calculate_tcp_packets_per_second(filepath, sample_rate=SAMPLE_RATE):
    """
    Reads a pcapng file, filters for TCP packets, and calculates
    packets per second over time intervals using tshark directly.
    """
    print(f"Processing {os.path.basename(filepath)}...")
    
    try:
        # Use tshark directly to extract only TCP packet timestamps
        # This is much faster than using pyshark as it avoids Python overhead
        filter_cmd = 'tcp' if sample_rate >= 1.0 else f'tcp and (frame.number % {int(1/sample_rate)} == 0)'
        
        cmd = [
            'tshark', '-r', filepath, 
            '-Y', filter_cmd,
            '-T', 'fields', '-e', 'frame.time_epoch',
            '-E', 'separator=,', '-E', 'header=y', '-E', 'quote=d'
        ]
        
        print(f"Running tshark command to extract TCP packet timestamps...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running tshark: {result.stderr}")
            return None, None
            
        # Parse timestamps from the output
        timestamps = []
        lines = result.stdout.strip().split('\n')
        
        # Skip header line
        if len(lines) > 1:
            for line in lines[1:]:
                if line.strip():
                    # Strip any quotes from the timestamp string before converting to float
                    timestamp_str = line.strip().strip('"\'')
                    timestamps.append(float(timestamp_str))
        
        total_packets = len(timestamps)
        print(f"Extracted {total_packets} TCP packet timestamps")
        
        if sample_rate < 1.0:
            estimated_total = int(total_packets / sample_rate)
            print(f"Sampled at {sample_rate*100:.1f}% - Estimated total packets: ~{estimated_total}")
        
    except FileNotFoundError:
        print("Error: TShark (part of Wireshark) not found.")
        print("Please install Wireshark and ensure TShark is in your system's PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file {filepath}: {e}")
        return None, None

    if not timestamps:
        print(f"No TCP packets found in {os.path.basename(filepath)}.")
        return np.array([]), np.array([])

    timestamps = np.array(timestamps)
    timestamps.sort()  # Ensure timestamps are sorted

    start_time = timestamps[0]
    end_time = timestamps[-1]
    duration = end_time - start_time

    if duration <= 0:
        print(f"Warning: Only one TCP packet or all packets have the same timestamp in {os.path.basename(filepath)}.")
        relative_time = np.array([0.0])
        packets_per_interval = np.array([len(timestamps)])
        return relative_time, packets_per_interval

    # Create time bins based on the defined interval
    bins = np.arange(start_time, end_time + TIME_INTERVAL, TIME_INTERVAL)

    # Count packets in each bin
    counts, _ = np.histogram(timestamps, bins=bins)
    
    # Apply sample rate correction if sampling was used
    if sample_rate < 1.0:
        counts = counts / sample_rate

    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    # Packets per second for each interval
    packets_per_second = counts / TIME_INTERVAL

    print(f"Finished processing {os.path.basename(filepath)}. Found {len(timestamps)} TCP packets over {duration:.2f} seconds.")
    return relative_bin_starts, packets_per_second

def plot_comparison(file_data):
    """Plots the packets/s comparison for the given pcap files."""
    plt.figure(figsize=(12, 6))

    for filename, data in file_data.items():
        times, pps = data
        if times is not None and pps is not None and len(times) > 0:
            plt.plot(times, pps, label=f"{os.path.basename(filename)} (TCP)", marker='.', linestyle='-')
        else:
             print(f"Skipping plot for {os.path.basename(filename)} due to lack of data.")

    plt.xlabel(f"Time (seconds since first TCP packet, {TIME_INTERVAL}s intervals)")
    plt.ylabel("TCP Packets per Second")
    plt.title("TCP Packet Rate Comparison")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    print("Displaying plot...")
    plt.show()

def main():
    """Main function to find files, process them, and plot results."""
    pcap_files = find_pcapng_files(VAR_FOLDER)

    if not pcap_files:
        print(f"No .pcapng files found in the '{VAR_FOLDER}' directory.")
        return

    if len(pcap_files) != 2:
        print(f"Error: Expected exactly 2 .pcapng files in '{VAR_FOLDER}', but found {len(pcap_files)}.")
        print("Files found:", [os.path.basename(f) for f in pcap_files])
        return

    # Check file sizes and adjust sample rate for very large files
    file_sizes = {f: os.path.getsize(f) for f in pcap_files}
    sample_rates = {}
    
    for f, size in file_sizes.items():
        # Adjust sample rate based on file size
        # For files > 1GB, sample at 10%
        # For files > 500MB, sample at 20%
        # For files > 200MB, sample at 50%
        if size > 1_000_000_000:
            sample_rates[f] = 0.1
        elif size > 500_000_000:
            sample_rates[f] = 0.2
        elif size > 200_000_000:
            sample_rates[f] = 0.5
        else:
            sample_rates[f] = 1.0
            
        if sample_rates[f] < 1.0:
            print(f"File {os.path.basename(f)} is large ({size/1_000_000:.1f} MB), using {sample_rates[f]*100:.0f}% sampling")
    
    file1, file2 = pcap_files
    results = {}

    times1, pps1 = calculate_tcp_packets_per_second(file1, sample_rate=sample_rates[file1])
    if times1 is not None:
        results[file1] = (times1, pps1)

    times2, pps2 = calculate_tcp_packets_per_second(file2, sample_rate=sample_rates[file2])
    if times2 is not None:
        results[file2] = (times2, pps2)

    if not results:
        print("No data processed successfully from either file. Exiting.")
        return

    plot_comparison(results)

if __name__ == "__main__":
    # Ensure necessary libraries are installed
    try:
        import matplotlib
        import numpy
    except ImportError as e:
        print(f"Error: Missing required library - {e.name}")
        print("Please install it using: pip install matplotlib numpy")
        sys.exit(1)

    main()