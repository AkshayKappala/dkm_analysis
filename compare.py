#!/usr/bin/env python
"""
PCAP Analysis Tool for comparing network captures with and without DKM

This script analyzes .pcapng files to extract and compare TCP packet statistics
including packet rates, round-trip times, and throughput.
"""

import os
import sys
import argparse
import numpy as np

# Import modules from our pcap_analyzer package
from pcap_analyzer.utils import find_pcapng_files, get_durations, DEFAULT_CONFIG, ensure_dir_exists
from pcap_analyzer.packet_processing import (
    calculate_tcp_packets_per_second,
    calculate_tcp_rtt,
    calculate_tcp_throughput
)
from pcap_analyzer.plotting import (
    plot_packet_rate_comparison,
    plot_rtt_comparison,
    plot_throughput_comparison,
    plot_combined_normalized
)
from pcap_analyzer.analysis import add_comparison_analysis

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Analyze and compare pcap files")
    parser.add_argument("--input-dir", default="var", help="Directory containing pcap files (default: var)")
    parser.add_argument("--output-dir", default="pcap_analyzer/output", help="Directory for output plots (default: pcap_analyzer/output)")
    parser.add_argument("--time-interval", type=float, default=1.0, help="Time interval for binning (default: 1.0 sec)")
    parser.add_argument("--sample-rate", type=float, default=1.0, help="Sample rate for large files (default: 1.0)")
    parser.add_argument("--plot-type", choices=["full", "normalized", "overlap", "all"], default="all",
                        help="Types of plots to generate (default: all)")
    parser.add_argument("--no-save", action="store_true", help="Don't save plots to files")
    
    return parser.parse_args()

def main():
    """Main function to find files, process them, and plot results."""
    # Parse command line arguments
    args = parse_args()
    
    # Setup configuration
    config = {
        'var_folder': args.input_dir,
        'time_interval': args.time_interval,
        'sample_rate': args.sample_rate,
        'plot_type': args.plot_type,
        'save_plots': not args.no_save,
        'output_dir': args.output_dir
    }
    
    # Ensure output directory exists
    ensure_dir_exists(config['output_dir'])
    
    # Find pcap files
    pcap_files = find_pcapng_files(config['var_folder'])

    if not pcap_files:
        print(f"No .pcapng files found in the '{config['var_folder']}' directory.")
        return

    if len(pcap_files) != 2:
        print(f"Error: Expected exactly 2 .pcapng files in '{config['var_folder']}', but found {len(pcap_files)}.")
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
            sample_rates[f] = config['sample_rate']
            
        if sample_rates[f] < 1.0:
            print(f"File {os.path.basename(f)} is large ({size/1_000_000:.1f} MB), using {sample_rates[f]*100:.0f}% sampling")
    
    results = {}

    # Process all metrics for each file
    for file_path in pcap_files:
        file_results = {}
        
        # Get packet rate data
        times_pps, pps = calculate_tcp_packets_per_second(file_path, config['time_interval'], sample_rate=sample_rates[file_path])
        if times_pps is not None:
            file_results['pps'] = (times_pps, pps)
        
        # Get RTT data
        times_rtt, rtt = calculate_tcp_rtt(file_path, config['time_interval'], sample_rate=sample_rates[file_path])
        if times_rtt is not None:
            file_results['rtt'] = (times_rtt, rtt)
        
        # Get throughput data
        times_tput, throughput = calculate_tcp_throughput(file_path, config['time_interval'], sample_rate=sample_rates[file_path])
        if times_tput is not None:
            file_results['throughput'] = (times_tput, throughput)
        
        results[file_path] = file_results

    if not results:
        print("No data processed successfully from either file. Exiting.")
        return

    # Get durations of the files
    durations = get_durations(results)
    print("\n===== FILE DURATIONS =====")
    for file_path, duration in durations.items():
        print(f"{os.path.basename(file_path)}: {duration:.2f} seconds")
    
    # Plot all comparison types and analyze
    print("\nGenerating multiple comparison plots...")
    
    # PPS comparison
    pps_info = plot_packet_rate_comparison(results, config['output_dir'], config)
    add_comparison_analysis(pps_info, 'pps')
    
    # RTT comparison
    rtt_info = plot_rtt_comparison(results, config['output_dir'], config)
    add_comparison_analysis(rtt_info, 'rtt')
    
    # Throughput comparison
    throughput_info = plot_throughput_comparison(results, config['output_dir'], config)
    add_comparison_analysis(throughput_info, 'throughput')
    
    # Generate the combined normalized plot
    print("\nGenerating combined normalized plot...")
    plot_combined_normalized(results, config['output_dir'], config)
    
    print(f"\nAnalysis complete. All plots saved to {os.path.abspath(config['output_dir'])}")

if __name__ == "__main__":
    main()