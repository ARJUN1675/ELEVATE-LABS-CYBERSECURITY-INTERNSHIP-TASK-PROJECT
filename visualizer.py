# visualizer.py
import matplotlib.pyplot as plt
import os
import pandas as pd

def plot_top_ips_requests(df, out_path, top_n=20):
    """
    Plot top N IPs by request count (bar chart).
    """
    if df.empty:
        return None
    counts = df['ip'].value_counts().head(top_n)
    plt.figure(figsize=(10,6))
    counts.plot(kind='bar')
    plt.title(f"Top {top_n} IPs by request count")
    plt.ylabel("Requests")
    plt.xlabel("IP")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    return out_path

def plot_requests_over_time(df, out_path, ip=None):
    """
    Plot request rate over time (per minute). If ip provided, filter to that ip.
    """
    df2 = df.copy()
    if ip:
        df2 = df2[df2['ip'] == ip]
    if df2.empty:
        return None
    df2['minute'] = df2['time'].dt.floor('T')
    series = df2.groupby('minute').size()
    plt.figure(figsize=(12,5))
    series.plot()
    title = f"Requests over time {'for ' + ip if ip else ''}"
    plt.title(title)
    plt.ylabel("Requests per minute")
    plt.xlabel("Time")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    return out_path

def ensure_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
