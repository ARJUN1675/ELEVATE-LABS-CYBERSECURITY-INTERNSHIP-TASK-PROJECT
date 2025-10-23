# main.py
import argparse
import yaml
import os
from parsers import parse_apache_log, parse_ssh_auth_log
from analyzer import (
    detect_apache_bruteforce,
    detect_dos_by_rps,
    detect_ssh_bruteforce,
    detect_port_scanning,
    merge_incidents,
    cross_reference_blacklist
)
from visualizer import plot_top_ips_requests, plot_requests_over_time, ensure_dir
from blacklist import load_local_blacklist
from utils import export_incidents
from datetime import datetime

def load_config(path='config.yaml'):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Log File Analyzer for Intrusion Detection")
    parser.add_argument('--config', default='config.yaml', help='path to config file')
    parser.add_argument('--apache', help='path to apache log (combined format)')
    parser.add_argument('--ssh', help='path to ssh auth log')
    parser.add_argument('--year', type=int, default=None, help='year for SSH log parser (auth.log lacks year)')
    parser.add_argument('--outdir', default=None, help='override output dir from config')
    args = parser.parse_args()

    cfg = load_config(args.config)

    out_dir = args.outdir or cfg['report']['out_dir']
    plots_dir = cfg['plots']['out_dir']

    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(plots_dir, exist_ok=True)

    incidents_all = []

    blacklist_set = set()
    if cfg.get('blacklist', {}).get('enabled', False):
        local_bl = cfg['blacklist'].get('local_file')
        if local_bl:
            blacklist_set = load_local_blacklist(local_bl)
            print(f"[+] Loaded {len(blacklist_set)} blacklisted IPs from {local_bl}")

    # Apache analysis
    if args.apache:
        print(f"[+] Parsing Apache log: {args.apache}")
        df_ap = parse_apache_log(args.apache)
        # detections
        a1 = detect_apache_bruteforce(df_ap,
                                     status_code=401,
                                     threshold=cfg['apache']['401_threshold'],
                                     window_minutes=cfg['apache']['time_window_minutes'])
        a2 = detect_dos_by_rps(df_ap,
                               window_minutes=1,
                               rps_threshold=cfg['apache']['dos_req_per_min'])
        a3 = detect_port_scanning(df_ap,
                                  ip_col='ip',
                                  endpoint_col='endpoint',
                                  threshold_distinct=cfg['scanning']['distinct_endpoints_threshold'])
        incidents_all.extend(merge_incidents(a1, a2, a3))
        # Visuals
        top_plot = os.path.join(plots_dir, f"apache_top_ips_{datetime.now().strftime('%Y%m%d%H%M%S')}.png")
        plot_top_ips_requests(df_ap, top_plot, top_n=cfg['plots']['top_n_ips'])
        print(f"[+] Saved top IPs plot to {top_plot}")

        # requests over time
        r_plot = os.path.join(plots_dir, f"apache_requests_over_time_{datetime.now().strftime('%Y%m%d%H%M%S')}.png")
        plot_requests_over_time(df_ap, r_plot)
        print(f"[+] Saved requests-over-time to {r_plot}")

    # SSH analysis
    if args.ssh:
        print(f"[+] Parsing SSH auth log: {args.ssh}")
        df_ssh = parse_ssh_auth_log(args.ssh, year=args.year)
        s1 = detect_ssh_bruteforce(df_ssh,
                                  failed_keyword='Failed password',
                                  threshold=cfg['ssh']['failed_threshold'],
                                  window_minutes=cfg['ssh']['time_window_minutes'])
        incidents_all.extend(merge_incidents(s1))

    # cross reference blacklist
    incidents_all = cross_reference_blacklist(incidents_all, blacklist_set)

    # export
    exported = export_incidents(incidents_all, out_dir, formats=cfg['report']['format'])
    print(f"[+] Exported incidents: {exported}")

    print(f"[+] Found {len(incidents_all)} incidents.")
    for inc in incidents_all:
        print(inc)

if __name__ == "__main__":
    main()
