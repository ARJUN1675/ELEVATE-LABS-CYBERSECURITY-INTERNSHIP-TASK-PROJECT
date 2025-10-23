# utils.py
import os
import json
import pandas as pd

def export_incidents(incidents, out_dir, base_name="incidents", formats=("csv","json")):
    os.makedirs(out_dir, exist_ok=True)
    df = pd.DataFrame(incidents)
    paths = {}
    if "csv" in formats:
        csv_path = os.path.join(out_dir, f"{base_name}.csv")
        df.to_csv(csv_path, index=False)
        paths['csv'] = csv_path
    if "json" in formats:
        json_path = os.path.join(out_dir, f"{base_name}.json")
        df.to_json(json_path, orient='records', date_format='iso')
        paths['json'] = json_path
    return paths
