import os
import numpy as np

def add_comparison_analysis(file_info, metric_type):
    """
    Print comparative analysis between files for a specific metric.
    """
    if len(file_info) < 2:
        print(f"Skipping {metric_type} comparison analysis - need at least 2 files.")
        return
    
    print(f"\n===== {metric_type.upper()} COMPARISON ANALYSIS =====")
    
    filenames = list(file_info.keys())
    base_filenames = [os.path.basename(f) for f in filenames]
    
    # Metric-specific analysis
    if metric_type == 'pps':
        # Compare average packet rates
        print("Average TCP Packet Rates:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['avg_pps']:.2f} packets/sec")
        
        # Compare ratios if there are exactly 2 files
        if len(file_info) == 2:
            ratio = file_info[filenames[0]]['avg_pps'] / file_info[filenames[1]]['avg_pps']
            print(f"Ratio of average packet rates ({base_filenames[0]} / {base_filenames[1]}): {ratio:.2f}")
            
        # Compare total packets
        print("\nTotal TCP Packets:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['total_packets']:.0f} packets")
            
    elif metric_type == 'rtt':
        # Compare average RTT
        print("Average TCP Round Trip Times:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['avg_rtt']:.2f} ms")
        
        # Compare ratios if there are exactly 2 files
        if len(file_info) == 2:
            ratio = file_info[filenames[0]]['avg_rtt'] / file_info[filenames[1]]['avg_rtt']
            print(f"Ratio of average RTT ({base_filenames[0]} / {base_filenames[1]}): {ratio:.2f}")
            
        # Compare min and max RTT
        print("\nMinimum TCP Round Trip Times:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['min_rtt']:.2f} ms")
            
        print("\nMaximum TCP Round Trip Times:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['max_rtt']:.2f} ms")
            
    elif metric_type == 'throughput':
        # Compare average throughput
        print("Average TCP Throughput:")
        for fname, info in file_info.items():
            print(f"  {os.path.basename(fname)}: {info['avg_throughput']:.2f} Mbps")
        
        # Compare ratios if there are exactly 2 files
        if len(file_info) == 2:
            ratio = file_info[filenames[0]]['avg_throughput'] / file_info[filenames[1]]['avg_throughput']
            print(f"Ratio of average throughput ({base_filenames[0]} / {base_filenames[1]}): {ratio:.2f}")
            
        # Compare total data transferred
        print("\nTotal Data Transferred:")
        for fname, info in file_info.items():
            mb_transferred = info['total_bits'] / 8 / 1_000_000
            print(f"  {os.path.basename(fname)}: {mb_transferred:.2f} MB")
    
    # Time-based efficiency analysis for all metrics
    if len(file_info) == 2:
        # Get durations
        durations = [info['duration'] for info in file_info.values()]
        print(f"\nTime Efficiency Analysis:")
        print(f"  {base_filenames[0]} duration: {durations[0]:.2f} seconds")
        print(f"  {base_filenames[1]} duration: {durations[1]:.2f} seconds")
        
        # If one file took longer than the other, calculate efficiency
        if abs(durations[0] - durations[1]) > 1.0:  # If difference > 1 second
            time_ratio = durations[0] / durations[1]
            faster_file = 0 if durations[0] < durations[1] else 1
            slower_file = 1 - faster_file
            time_diff = abs(durations[0] - durations[1])
            
            print(f"  {base_filenames[faster_file]} completed {time_diff:.2f} seconds faster")
            print(f"  Time ratio: {base_filenames[slower_file]} took {time_ratio:.2f}x longer to complete")

def prepare_packet_rate_data(file_data, time_interval):
    """
    Prepare packet rate data for plotting and analysis.
    """
    file_info = {}
    
    for filename, data in file_data.items():
        if 'pps' not in data or data['pps'][0] is None or len(data['pps'][0]) == 0:
            print(f"Skipping plot for {os.path.basename(filename)} due to lack of data.")
            continue
            
        times, pps = data['pps']
        duration = times[-1] if len(times) > 0 else 0
        file_info[filename] = {
            'times': times,
            'pps': pps,
            'duration': duration,
            'avg_pps': np.mean(pps),
            'max_pps': np.max(pps),
            'total_packets': np.sum(pps * time_interval)
        }
    
    return file_info

def prepare_rtt_data(file_data):
    """
    Prepare RTT data for plotting and analysis.
    """
    file_info = {}
    
    for filename, data in file_data.items():
        if 'rtt' not in data or data['rtt'][0] is None or len(data['rtt'][0]) == 0:
            print(f"Skipping RTT plot for {os.path.basename(filename)} due to lack of data.")
            continue
            
        times, rtt = data['rtt']
        
        # Filter out NaN values for statistics
        valid_rtt = rtt[~np.isnan(rtt)]
        if len(valid_rtt) == 0:
            print(f"Skipping RTT plot for {os.path.basename(filename)} due to lack of valid RTT data.")
            continue
            
        duration = times[-1] if len(times) > 0 else 0
        file_info[filename] = {
            'times': times,
            'rtt': rtt,
            'duration': duration,
            'avg_rtt': np.nanmean(rtt),
            'max_rtt': np.nanmax(rtt),
            'min_rtt': np.nanmin(rtt),
            'median_rtt': np.nanmedian(rtt)
        }
    
    return file_info

def prepare_throughput_data(file_data, time_interval):
    """
    Prepare throughput data for plotting and analysis.
    """
    file_info = {}
    
    for filename, data in file_data.items():
        if 'throughput' not in data or data['throughput'][0] is None or len(data['throughput'][0]) == 0:
            print(f"Skipping throughput plot for {os.path.basename(filename)} due to lack of data.")
            continue
            
        times, throughput = data['throughput']
        # Convert to Mbps for better readability
        throughput_mbps = throughput / 1_000_000
        
        duration = times[-1] if len(times) > 0 else 0
        file_info[filename] = {
            'times': times,
            'throughput': throughput_mbps,
            'duration': duration,
            'avg_throughput': np.mean(throughput_mbps),
            'max_throughput': np.max(throughput_mbps),
            'total_bits': np.sum(throughput * time_interval),  # Original bits, not Mbps
            'avg_bandwidth': np.sum(throughput) / len(throughput) if len(throughput) > 0 else 0
        }
    
    return file_info