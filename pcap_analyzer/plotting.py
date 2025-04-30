import os
import matplotlib.pyplot as plt
import numpy as np
from pcap_analyzer.utils import COLORS, STYLES, get_output_path, clean_filename

def plot_full_view(file_info, title, ylabel, filename_prefix, output_dir, y_metric='pps', save_plots=True):
    """
    Plot the full data view of all files for comparison.
    This shows the complete duration of all captures.
    """
    plt.figure(figsize=(12, 6))
    
    # Remove "TCP" from title and ylabel
    title = title.replace("TCP ", "")
    ylabel = ylabel.replace("TCP ", "")
    
    plt.title(title)
    
    # Create common x-axis for all files
    max_duration = max([info['duration'] for info in file_info.values()])
    
    # Plot each file's data
    for i, (filename, info) in enumerate(file_info.items()):
        style = STYLES[i % len(STYLES)]
        
        plt.plot(info['times'], info[y_metric], 
                 label=f"{clean_filename(filename)}", 
                 color=COLORS[0], linestyle=style)
        
        # Add annotation at the end showing total duration
        if len(info[y_metric]) > 0:
            last_point_x = info['times'][-1]
            last_point_y = info[y_metric][-1]
            plt.annotate(f'{info["duration"]:.2f}s', 
                         xy=(last_point_x, last_point_y),
                         xytext=(0, 0),
                         textcoords="offset points",
                         color=COLORS[0],
                         fontsize=8)
    
    plt.xlim(0, max_duration)
    plt.xlabel("Time (seconds)")
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3)
    plt.legend()
    
    # Add more space at the bottom for the legend
    plt.subplots_adjust(bottom=0.2)
    
    if save_plots:
        output_path = get_output_path(filename_prefix, output_dir)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved plot to {output_path}")
        
    plt.close()

def plot_normalized_view(file_info, title, ylabel, filename_prefix, output_dir, y_metric='pps', save_plots=True):
    """
    Plot the normalized view where each file's timeline is scaled to match.
    This helps compare patterns regardless of duration differences.
    """
    plt.figure(figsize=(12, 6))
    
    # Remove "TCP" from title and ylabel
    title = title.replace("TCP ", "")
    ylabel = ylabel.replace("TCP ", "")
    
    plt.title(title)
    
    # Plot each file's data with normalized time
    for i, (filename, info) in enumerate(file_info.items()):
        style = STYLES[i % len(STYLES)]
        
        # Normalize time to percentage of total duration
        normalized_times = info['times'] / info['duration'] * 100
        
        plt.plot(normalized_times, info[y_metric], 
                 label=f"{clean_filename(filename)}", 
                 color=COLORS[0], linestyle=style)
        
        # Add annotation at the end showing total duration
        if len(info[y_metric]) > 0:
            last_point_x = normalized_times[-1]
            last_point_y = info[y_metric][-1]
            plt.annotate(f'{info["duration"]:.2f}s', 
                         xy=(last_point_x, last_point_y),
                         xytext=(0, 0),
                         textcoords="offset points",
                         color=COLORS[0],
                         fontsize=8)
    
    plt.xlim(0, 100)
    plt.xlabel("Time (% of total duration)")
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3)
    plt.legend()
    
    # Add more space at the bottom for the legend
    plt.subplots_adjust(bottom=0.2)
    
    if save_plots:
        output_path = get_output_path(filename_prefix, output_dir)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved plot to {output_path}")
        
    plt.close()

def plot_log_scale_view(file_info, title, ylabel, filename_prefix, output_dir, y_metric='pps', save_plots=True):
    """
    Plot the data with a logarithmic y-axis and normalized x-axis to better see details.
    """
    plt.figure(figsize=(12, 6))
    
    # Remove "TCP" from title
    title = title.replace("TCP ", "")
    # Remove "TCP" from ylabel
    ylabel = ylabel.replace("TCP ", "")
    
    plt.title(f"{title} (Log Scale)")
    
    # For each file's data, normalize x-axis to 0-100% and plot
    for i, (filename, info) in enumerate(file_info.items()):
        style = STYLES[i % len(STYLES)]
        
        # Normalize time to percentage of total duration
        normalized_times = info['times'] / info['duration'] * 100
        
        # For log scale, replace zeros with a small value
        values = info[y_metric].copy()
        values[values <= 0] = 0.01  # Small positive value for log scale
        
        line, = plt.semilogy(normalized_times, values, 
                     label=f"{clean_filename(filename)}", 
                     color=COLORS[0], linestyle=style)
        
        # Add annotation at the end showing total duration
        if len(values) > 0:
            last_point_x = normalized_times[-1]
            last_point_y = values[-1]
            plt.annotate(f'{info["duration"]:.2f}s', 
                         xy=(last_point_x, last_point_y),
                         xytext=(0, 0),
                         textcoords="offset points",
                         color=COLORS[0],
                         fontsize=8)
    
    plt.xlim(0, 100)
    plt.xlabel("Time (% of total duration)")
    plt.ylabel(ylabel)
    plt.grid(True, alpha=0.3, which='both')
    plt.legend()
    
    # Add more space at the bottom for the legend
    plt.subplots_adjust(bottom=0.2)
    
    if save_plots:
        output_path = get_output_path(filename_prefix, output_dir)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved plot to {output_path}")
        
    plt.close()

def plot_packet_rate_comparison(file_data, output_dir, config):
    """
    Plots the packets/s comparison for the given pcap files using different views.
    """
    from pcap_analyzer.analysis import prepare_packet_rate_data
    
    # Get data from each file and calculate max duration
    file_info = prepare_packet_rate_data(file_data, config['time_interval'])
    
    if not file_info:
        print("No data to plot for packet rate comparison.")
        return
    
    # Create only normalized and log scale plots as specified
    plot_normalized_view(file_info, "TCP Packet Rate Comparison - Normalized Time", 
                        "TCP Packets per Second", "packet_rate_normalized", output_dir, 
                        'pps', config['save_plots'])
    
    plot_log_scale_view(file_info, "TCP Packet Rate Comparison", "TCP Packets per Second", 
                       "packet_rate_log", output_dir, 'pps', config['save_plots'])
    
    return file_info

def plot_rtt_comparison(file_data, output_dir, config):
    """
    Plots the RTT comparison for the given pcap files using different views.
    """
    from pcap_analyzer.analysis import prepare_rtt_data
    
    # Get data from each file and calculate max duration
    file_info = prepare_rtt_data(file_data)
    
    if not file_info:
        print("No data to plot for RTT comparison.")
        return
    
    # Create only normalized and log scale plots as specified
    plot_normalized_view(file_info, "TCP Round Trip Time Comparison - Normalized Time", 
                        "TCP Round Trip Time (ms)", "rtt_normalized", output_dir, 
                        'rtt', config['save_plots'])
    
    plot_log_scale_view(file_info, "TCP Round Trip Time Comparison", "TCP Round Trip Time (ms)", 
                       "rtt_log", output_dir, 'rtt', config['save_plots'])
    
    return file_info

def plot_throughput_comparison(file_data, output_dir, config):
    """
    Plots the throughput comparison for the given pcap files using different views.
    """
    from pcap_analyzer.analysis import prepare_throughput_data
    
    # Get data from each file and calculate max duration
    file_info = prepare_throughput_data(file_data, config['time_interval'])
    
    if not file_info:
        print("No data to plot for throughput comparison.")
        return
    
    # Create only normalized and log scale plots as specified  
    plot_normalized_view(file_info, "TCP Throughput Comparison - Normalized Time", 
                        "TCP Throughput (Mbps)", "throughput_normalized", output_dir, 
                        'throughput', config['save_plots'])
    
    plot_log_scale_view(file_info, "TCP Throughput Comparison", "TCP Throughput (Mbps)", 
                       "throughput_log", output_dir, 'throughput', config['save_plots'])
    
    return file_info

def plot_combined_normalized(file_data, output_dir, config):
    """
    Creates a combined visualization with all three normalized metrics
    (packet rate, RTT, throughput) in a single plot for easy comparison.
    """
    from pcap_analyzer.analysis import prepare_packet_rate_data, prepare_rtt_data, prepare_throughput_data
    
    # Get data for all three metrics
    pps_info = prepare_packet_rate_data(file_data, config['time_interval'])
    rtt_info = prepare_rtt_data(file_data)
    throughput_info = prepare_throughput_data(file_data, config['time_interval'])
    
    if not pps_info or not rtt_info or not throughput_info:
        print("Missing data for combined plot. Need all three metrics.")
        return
    
    # Create a figure with three subplots (one for each metric)
    fig, axes = plt.subplots(3, 1, figsize=(12, 12), sharex=True)
    
    # Define metrics info for consistent plotting
    metrics = [
        {'data': pps_info, 'name': 'Packet Rate', 'unit': 'Packets per Second', 'key': 'pps'},
        {'data': rtt_info, 'name': 'Round Trip Time', 'unit': 'ms', 'key': 'rtt'},
        {'data': throughput_info, 'name': 'Throughput', 'unit': 'Mbps', 'key': 'throughput'}
    ]
    
    # Store legend handles to avoid the error
    legend_handles = []
    
    # Plot each metric in its respective subplot
    for i, metric in enumerate(metrics):
        ax = axes[i]
        
        # Set title and labels
        ax.set_title(f"{metric['name']} Comparison - Normalized Time", fontsize=10)
        ax.set_ylabel(f"{metric['name']} ({metric['unit']})")
        
        # Add grid
        ax.grid(True, alpha=0.3)
        
        # Plot each file's data
        for j, (filename, info) in enumerate(metric['data'].items()):
            style = STYLES[j % len(STYLES)]
            
            # Normalize time to percentage of total duration
            normalized_times = info['times'] / info['duration'] * 100
            
            # Plot the data
            line, = ax.plot(normalized_times, info[metric['key']], 
                         color=COLORS[0], linestyle=style)
            
            # Only add to legend in the first subplot to avoid duplication
            if i == 0:
                legend_handles.append((line, clean_filename(filename)))
            
            # Add annotation at the end showing total duration
            if len(info[metric['key']]) > 0:
                last_point_x = normalized_times[-1]
                last_point_y = info[metric['key']][-1]
                ax.annotate(f'{info["duration"]:.2f}s', 
                         xy=(last_point_x, last_point_y),
                         xytext=(0, 0),
                         textcoords="offset points",
                         color=COLORS[0],
                         fontsize=8)
        
        # Set x-axis limits
        ax.set_xlim(0, 100)
    
    # Add a common x-axis label to the bottom subplot
    axes[2].set_xlabel("Time (% of total duration)")
    
    # Create a custom legend with file names in figure level, but only if we have legend data
    if legend_handles:
        legend_lines, legend_labels = zip(*legend_handles)
        fig.legend(legend_lines, legend_labels, loc='upper center', bbox_to_anchor=(0.5, 0.98),
                  ncol=len(legend_handles), frameon=True)
    
    # Adjust spacing
    plt.tight_layout()
    plt.subplots_adjust(top=0.9, hspace=0.3)
    
    # Save the combined plot
    if config['save_plots']:
        output_path = get_output_path("combined_normalized", output_dir)
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        print(f"Saved combined normalized plot to {output_path}")
    
    plt.close()