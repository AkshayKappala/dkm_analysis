import os
import matplotlib.pyplot as plt
import numpy as np
import subprocess
import sys
from collections import defaultdict

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

def calculate_tcp_rtt(filepath, sample_rate=SAMPLE_RATE):
    """
    Extracts round-trip time data from a pcapng file using tshark.
    Returns times and RTT values binned by TIME_INTERVAL.
    """
    print(f"Processing {os.path.basename(filepath)} for RTT analysis...")
    
    try:
        # Use tshark to extract TCP RTT values (tcp.analysis.ack_rtt)
        filter_cmd = 'tcp.analysis.ack_rtt' if sample_rate >= 1.0 else f'tcp.analysis.ack_rtt and (frame.number % {int(1/sample_rate)} == 0)'
        
        cmd = [
            'tshark', '-r', filepath, 
            '-Y', filter_cmd,
            '-T', 'fields', 
            '-e', 'frame.time_epoch', 
            '-e', 'tcp.analysis.ack_rtt',
            '-E', 'separator=,', '-E', 'header=y', '-E', 'quote=d'
        ]
        
        print(f"Running tshark command to extract TCP RTT data...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running tshark: {result.stderr}")
            return None, None
            
        # Parse data from the output
        timestamps = []
        rtt_values = []
        lines = result.stdout.strip().split('\n')
        
        # Skip header line
        if len(lines) > 1:
            for line in lines[1:]:
                if line.strip() and ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
                        try:
                            time_str = parts[0].strip().strip('"\'')
                            rtt_str = parts[1].strip().strip('"\'')
                            timestamps.append(float(time_str))
                            rtt_values.append(float(rtt_str) * 1000)  # Convert to milliseconds
                        except (ValueError, IndexError):
                            continue
        
        total_rtts = len(rtt_values)
        print(f"Extracted {total_rtts} TCP RTT measurements")
        
        if sample_rate < 1.0:
            estimated_total = int(total_rtts / sample_rate)
            print(f"Sampled at {sample_rate*100:.1f}% - Estimated total RTT measurements: ~{estimated_total}")
        
    except Exception as e:
        print(f"Error processing file {filepath} for RTT: {e}")
        return None, None

    if not timestamps or not rtt_values:
        print(f"No RTT data found in {os.path.basename(filepath)}.")
        return np.array([]), np.array([])

    timestamps = np.array(timestamps)
    rtt_values = np.array(rtt_values)
    
    # Sort data by timestamp
    sort_indices = np.argsort(timestamps)
    timestamps = timestamps[sort_indices]
    rtt_values = rtt_values[sort_indices]

    start_time = timestamps[0]
    end_time = timestamps[-1]
    duration = end_time - start_time

    if duration <= 0:
        print(f"Warning: RTT data spans zero time in {os.path.basename(filepath)}.")
        return np.array([0.0]), np.array([np.mean(rtt_values)])

    # Create time bins based on the defined interval
    bins = np.arange(start_time, end_time + TIME_INTERVAL, TIME_INTERVAL)
    
    # Calculate average RTT for each time bin
    digitized = np.digitize(timestamps, bins)
    rtt_by_time_bin = [rtt_values[digitized == i] for i in range(1, len(bins))]
    
    # Calculate mean RTT for each time bin (use NaN for empty bins)
    mean_rtt = np.array([np.mean(rtts) if len(rtts) > 0 else np.nan for rtts in rtt_by_time_bin])
    
    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    print(f"Finished RTT analysis for {os.path.basename(filepath)}. Found {len(rtt_values)} RTT measurements over {duration:.2f} seconds.")
    return relative_bin_starts, mean_rtt

def calculate_tcp_throughput(filepath, sample_rate=SAMPLE_RATE):
    """
    Calculates throughput (bits per second) for a pcapng file using tshark.
    Returns times and throughput values binned by TIME_INTERVAL.
    """
    print(f"Processing {os.path.basename(filepath)} for throughput analysis...")
    
    try:
        # Use tshark to extract frame time and length
        filter_cmd = 'tcp' if sample_rate >= 1.0 else f'tcp and (frame.number % {int(1/sample_rate)} == 0)'
        
        cmd = [
            'tshark', '-r', filepath, 
            '-Y', filter_cmd,
            '-T', 'fields', 
            '-e', 'frame.time_epoch', 
            '-e', 'frame.len',
            '-E', 'separator=,', '-E', 'header=y', '-E', 'quote=d'
        ]
        
        print(f"Running tshark command to extract frame data for throughput calculation...")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"Error running tshark: {result.stderr}")
            return None, None
            
        # Parse data from the output
        timestamps = []
        frame_sizes = []
        lines = result.stdout.strip().split('\n')
        
        # Skip header line
        if len(lines) > 1:
            for line in lines[1:]:
                if line.strip() and ',' in line:
                    parts = line.strip().split(',')
                    if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
                        try:
                            time_str = parts[0].strip().strip('"\'')
                            size_str = parts[1].strip().strip('"\'')
                            timestamps.append(float(time_str))
                            frame_sizes.append(int(size_str))
                        except (ValueError, IndexError):
                            continue
        
        total_frames = len(frame_sizes)
        print(f"Extracted {total_frames} TCP frames for throughput calculation")
        
        if sample_rate < 1.0:
            estimated_total = int(total_frames / sample_rate)
            print(f"Sampled at {sample_rate*100:.1f}% - Estimated total frames: ~{estimated_total}")
        
    except Exception as e:
        print(f"Error processing file {filepath} for throughput: {e}")
        return None, None

    if not timestamps or not frame_sizes:
        print(f"No frame data found in {os.path.basename(filepath)}.")
        return np.array([]), np.array([])

    timestamps = np.array(timestamps)
    frame_sizes = np.array(frame_sizes)
    
    # Sort data by timestamp
    sort_indices = np.argsort(timestamps)
    timestamps = timestamps[sort_indices]
    frame_sizes = frame_sizes[sort_indices]

    start_time = timestamps[0]
    end_time = timestamps[-1]
    duration = end_time - start_time

    if duration <= 0:
        print(f"Warning: Frame data spans zero time in {os.path.basename(filepath)}.")
        total_bits = np.sum(frame_sizes) * 8
        return np.array([0.0]), np.array([total_bits])

    # Create time bins based on the defined interval
    bins = np.arange(start_time, end_time + TIME_INTERVAL, TIME_INTERVAL)
    
    # Sum up the frame sizes for each time bin
    digitized = np.digitize(timestamps, bins)
    sizes_by_time_bin = [frame_sizes[digitized == i] for i in range(1, len(bins))]
    
    # Calculate total bits for each time bin and convert to bits per second
    bits_per_second = np.array([np.sum(sizes) * 8 / TIME_INTERVAL if len(sizes) > 0 else 0 
                               for sizes in sizes_by_time_bin])
    
    # If sampling was used, adjust the throughput values
    if sample_rate < 1.0:
        bits_per_second = bits_per_second / sample_rate
    
    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    print(f"Finished throughput analysis for {os.path.basename(filepath)}. Analyzed {len(frame_sizes)} frames over {duration:.2f} seconds.")
    return relative_bin_starts, bits_per_second

def plot_packet_rate_comparison(file_data):
    """Plots the packets/s comparison for the given pcap files."""
    plt.figure(figsize=(12, 6))

    for filename, data in file_data.items():
        times, pps = data['pps']
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
    print("Displaying packet rate plot...")
    plt.savefig('packet_rate_comparison.png')
    plt.show()

def plot_rtt_comparison(file_data):
    """Plots the RTT comparison for the given pcap files."""
    plt.figure(figsize=(12, 6))

    for filename, data in file_data.items():
        times, rtt = data['rtt']
        if times is not None and rtt is not None and len(times) > 0:
            plt.plot(times, rtt, label=f"{os.path.basename(filename)} (TCP)", marker='.', linestyle='-')
        else:
             print(f"Skipping RTT plot for {os.path.basename(filename)} due to lack of data.")

    plt.xlabel(f"Time (seconds since first TCP packet, {TIME_INTERVAL}s intervals)")
    plt.ylabel("TCP Round Trip Time (ms)")
    plt.title("TCP Round Trip Time Comparison")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    print("Displaying RTT plot...")
    plt.savefig('rtt_comparison.png')
    plt.show()

def plot_throughput_comparison(file_data):
    """Plots the throughput comparison for the given pcap files."""
    plt.figure(figsize=(12, 6))

    for filename, data in file_data.items():
        times, throughput = data['throughput']
        if times is not None and throughput is not None and len(times) > 0:
            # Convert to Mbps for better readability
            throughput_mbps = throughput / 1_000_000
            plt.plot(times, throughput_mbps, label=f"{os.path.basename(filename)} (TCP)", marker='.', linestyle='-')
        else:
             print(f"Skipping throughput plot for {os.path.basename(filename)} due to lack of data.")

    plt.xlabel(f"Time (seconds since first TCP packet, {TIME_INTERVAL}s intervals)")
    plt.ylabel("TCP Throughput (Mbps)")
    plt.title("TCP Throughput Comparison")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    print("Displaying throughput plot...")
    plt.savefig('throughput_comparison.png')
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

    # Process all metrics for each file
    for file_path in pcap_files:
        file_results = {}
        
        # Get packet rate data
        times_pps, pps = calculate_tcp_packets_per_second(file_path, sample_rate=sample_rates[file_path])
        if times_pps is not None:
            file_results['pps'] = (times_pps, pps)
        
        # Get RTT data
        times_rtt, rtt = calculate_tcp_rtt(file_path, sample_rate=sample_rates[file_path])
        if times_rtt is not None:
            file_results['rtt'] = (times_rtt, rtt)
        
        # Get throughput data
        times_tput, throughput = calculate_tcp_throughput(file_path, sample_rate=sample_rates[file_path])
        if times_tput is not None:
            file_results['throughput'] = (times_tput, throughput)
        
        results[file_path] = file_results

    if not results:
        print("No data processed successfully from either file. Exiting.")
        return

    # Plot all three comparisons
    plot_packet_rate_comparison(results)
    plot_rtt_comparison(results)
    plot_throughput_comparison(results)

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