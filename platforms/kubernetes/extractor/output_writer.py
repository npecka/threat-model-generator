# output_writer.py

import json

def write_output(output_data):
    with open("output/k8s_enhanced_metadata.json", "w") as f:
        json.dump(output_data, f, indent=4)
