# analyzer.py
from collections import defaultdict, Counter
from datetime import timedelta
import pandas as pd

def sliding_time_window_counts(df, time_col='time', ip_col='ip', window_minutes=5):
    """
    For each IP, compute number of events inside a rolling window (per event).
    Returns dict: {ip: list of (timestamp, count_in_window)}
    """
    results = {}
    grouped = df.groupby(ip_col)
    for ip, g in grouped:
        times = g[time_col].sort_values().tolist()
        counts = []
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > timedelta(minutes=window_minutes):
                left += 1
            counts.append((times[right], right - left + 1))
        results[ip] = counts
    return results

def detect_apache_bruteforce(df, status_code=401, threshold=20, window_minutes=5):
    """
    Identify IPs with >= threshold occurrences of status_code in window.
    Returns list of dict incidents.
    """
    df401 = df[df['status'] == status_code]
    if df401.empty:
        return []
    counts = sliding_time_window_counts(df401, time_col='time', ip_col='ip', window_minutes=window_minutes)
    incidents = []
    for ip, lst in counts.items():
        max_count = max([c for _, c in lst]) if lst else 0
        if max_count >= threshold:
            time_of_peak = max(lst, key=lambda x: x[1])[0]
            incidents.append({
                'type': 'apache_bruteforce',
                'ip': ip,
                'status_code': status_code,
                'max_count': max_count,
                'time': time_of_peak
            })
    return incidents

def detect_dos_by_rps(df, window_minutes=1, rps_threshold=120):
    """
    Detect IPs exceeding requests-per-minute threshold (approx).
    Returns incidents list.
    """
    # create per-minute bins
    df = df.copy()
    df['minute'] = df['time'].dt.floor('T')
    grouped = df.groupby(['ip', 'minute']).size().reset_index(name='count')
    incidents = []
    for ip, g in grouped.groupby('ip'):
        max_row = g.loc[g['count'].idxmax()]
        if max_row['count'] >= rps_threshold:
            incidents.append({
                'type': 'dos_like',
                'ip': ip,
                'requests_in_minute': int(max_row['count']),
                'minute': pd.to_datetime(max_row['minute'])
            })
    return incidents

def detect_ssh_bruteforce(df, failed_keyword='Failed password', threshold=10, window_minutes=10):
    """
    df: parsed ssh dataframe with 'msg' and 'ip' & 'time'.
    Identify IPs with many failed attempts.
    """
    df_failed = df[df['msg'].str.contains('Failed password', na=False)]
    if df_failed.empty:
        return []
    counts = sliding_time_window_counts(df_failed, time_col='time', ip_col='ip', window_minutes=window_minutes)
    incidents = []
    for ip, lst in counts.items():
        max_count = max([c for _, c in lst]) if lst else 0
        if max_count >= threshold:
            incidents.append({
                'type': 'ssh_bruteforce',
                'ip': ip,
                'max_failed': max_count,
                'time': max(lst, key=lambda x: x[1])[0]
            })
    return incidents

def detect_port_scanning(df, ip_col='ip', endpoint_col='endpoint', threshold_distinct=50):
    """
    For Apache logs, detect IPs that fetched many distinct endpoints quickly (simple scanning heuristic).
    """
    incidents = []
    grouped = df.groupby(ip_col)
    for ip, g in grouped:
        distinct = g[endpoint_col].nunique()
        if distinct >= threshold_distinct:
            incidents.append({
                'type': 'http_scanning',
                'ip': ip,
                'distinct_endpoints': int(distinct)
            })
    return incidents

def merge_incidents(*lists):
    merged = []
    for lst in lists:
        if lst:
            merged.extend(lst)
    # deduplicate by (type, ip, time) loosely
    seen = set()
    unique = []
    for inc in merged:
        key = (inc.get('type'), inc.get('ip'), str(inc.get('time', '')))
        if key not in seen:
            seen.add(key)
            unique.append(inc)
    return unique

def cross_reference_blacklist(incidents, blacklist_set):
    """
    Mark incidents with 'blacklisted': True if IP in blacklist_set
    """
    for inc in incidents:
        inc['blacklisted'] = inc.get('ip') in blacklist_set
    return incidents
