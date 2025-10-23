# parsers.py
import re
from datetime import datetime
import pandas as pd

APACHE_COMBINED_REGEX = re.compile(
    r'(?P<ip>\S+) '                  # IP
    r'(?P<ident>\S*) '               # ident
    r'(?P<userid>\S*) '              # userid
    r'\[(?P<time>[^\]]+)\] '         # time
    r'"(?P<request>[^"]+)" '         # request
    r'(?P<status>\d{3}) '            # status
    r'(?P<size>\S+) '                # size
    r'"(?P<referer>[^"]*)" '         # referer
    r'"(?P<agent>[^"]*)"'            # user-agent
)

APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"  # e.g., 10/Oct/2025:13:55:36 +0000

SSH_AUTH_REGEX = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w\-/]+)\[\d+\]:\s+(?P<msg>.*)'
)
# Many SSH messages will include "Failed password for", "Accepted password for", "invalid user" etc.

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def parse_apache_log(path):
    """
    Returns a pandas DataFrame with columns:
    ip, time (datetime), method, endpoint, protocol, status (int), size (int), referer, agent, raw_request
    """
    rows = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = APACHE_COMBINED_REGEX.match(line)
            if not m:
                continue
            gd = m.groupdict()
            try:
                t = datetime.strptime(gd['time'], APACHE_TIME_FORMAT)
            except Exception:
                # try to parse without timezone
                t = datetime.strptime(gd['time'].split()[0], "%d/%b/%Y:%H:%M:%S")
            request = gd['request']
            method, endpoint, proto = (None, None, None)
            parts = request.split()
            if len(parts) >= 3:
                method, endpoint, proto = parts[0], parts[1], parts[2]
            status = int(gd['status'])
            size = int(gd['size']) if gd['size'].isdigit() else 0
            rows.append({
                'ip': gd['ip'],
                'time': t,
                'method': method,
                'endpoint': endpoint,
                'protocol': proto,
                'status': status,
                'size': size,
                'referer': gd['referer'],
                'agent': gd['agent'],
                'raw_request': request,
                'raw_line': line.strip()
            })
    df = pd.DataFrame(rows)
    if not df.empty:
        df.sort_values('time', inplace=True)
    return df

def parse_ssh_auth_log(path, year=None):
    """
    Parse /var/log/auth.log-like files (ubuntu), return DataFrame with:
    time (datetime), ip (if present), user(if present), msg, raw_line
    Note: exact formats vary by distro; this function keeps the parsing simple & robust.
    """
    rows = []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = SSH_AUTH_REGEX.match(line)
            if not m:
                continue
            gd = m.groupdict()
            # Build datetime; auth.log doesn't include year -> use provided year or current year
            y = year
            if y is None:
                y = datetime.now().year
            month = MONTHS.get(gd['month'], 1)
            day = int(gd['day'])
            timeparts = list(map(int, gd['time'].split(':')))
            try:
                dt = datetime(y, month, day, timeparts[0], timeparts[1], timeparts[2])
            except Exception:
                dt = datetime.now()
            msg = gd['msg']
            # Try to extract IP and user
            ip = None
            user = None
            # common patterns
            ip_search = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', msg)
            if ip_search:
                ip = ip_search.group(1)
            user_search = re.search(r'for (\S+)\s', msg)
            if user_search:
                user = user_search.group(1)
            rows.append({
                'time': dt,
                'host': gd['host'],
                'service': gd['service'],
                'msg': msg,
                'ip': ip,
                'user': user,
                'raw_line': line.strip()
            })
    df = pd.DataFrame(rows)
    if not df.empty:
        df.sort_values('time', inplace=True)
    return df
