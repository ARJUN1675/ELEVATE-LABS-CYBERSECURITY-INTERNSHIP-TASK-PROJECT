# blacklist.py
def load_local_blacklist(path):
    s = set()
    try:
        with open(path, 'r') as f:
            for line in f:
                ip = line.strip()
                if not ip:
                    continue
                s.add(ip)
    except FileNotFoundError:
        return set()
    return s
