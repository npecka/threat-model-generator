# data_loader.py
import json

def load_data(file_path="output/k8s_enhanced_metadata.json"):
    with open(file_path) as f:
        return json.load(f)
