import os
import subprocess
import sys
import numpy as np

def calculate_tcp_packets_per_second(filepath, time_interval, sample_rate=1.0):
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
    bins = np.arange(start_time, end_time + time_interval, time_interval)

    # Count packets in each bin
    counts, _ = np.histogram(timestamps, bins=bins)
    
    # Apply sample rate correction if sampling was used
    if sample_rate < 1.0:
        counts = counts / sample_rate

    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    # Packets per second for each interval
    packets_per_second = counts / time_interval

    print(f"Finished processing {os.path.basename(filepath)}. Found {len(timestamps)} TCP packets over {duration:.2f} seconds.")
    return relative_bin_starts, packets_per_second

def calculate_tcp_rtt(filepath, time_interval, sample_rate=1.0):
    """
    Extracts round-trip time data from a pcapng file using tshark.
    Returns times and RTT values binned by time_interval.
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
    bins = np.arange(start_time, end_time + time_interval, time_interval)
    
    # Calculate average RTT for each time bin
    digitized = np.digitize(timestamps, bins)
    rtt_by_time_bin = [rtt_values[digitized == i] for i in range(1, len(bins))]
    
    # Calculate mean RTT for each time bin (use NaN for empty bins)
    mean_rtt = np.array([np.mean(rtts) if len(rtts) > 0 else np.nan for rtts in rtt_by_time_bin])
    
    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    print(f"Finished RTT analysis for {os.path.basename(filepath)}. Found {len(rtt_values)} RTT measurements over {duration:.2f} seconds.")
    return relative_bin_starts, mean_rtt

def calculate_tcp_throughput(filepath, time_interval, sample_rate=1.0):
    """
    Calculates throughput (bits per second) for a pcapng file using tshark.
    Returns times and throughput values binned by time_interval.
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
    bins = np.arange(start_time, end_time + time_interval, time_interval)
    
    # Sum up the frame sizes for each time bin
    digitized = np.digitize(timestamps, bins)
    sizes_by_time_bin = [frame_sizes[digitized == i] for i in range(1, len(bins))]
    
    # Calculate total bits for each time bin and convert to bits per second
    bits_per_second = np.array([np.sum(sizes) * 8 / time_interval if len(sizes) > 0 else 0 
                               for sizes in sizes_by_time_bin])
    
    # If sampling was used, adjust the throughput values
    if sample_rate < 1.0:
        bits_per_second = bits_per_second / sample_rate
    
    # Calculate the start time of each bin relative to the first packet
    relative_bin_starts = bins[:-1] - start_time

    print(f"Finished throughput analysis for {os.path.basename(filepath)}. Analyzed {len(frame_sizes)} frames over {duration:.2f} seconds.")
    return relative_bin_starts, bits_per_second