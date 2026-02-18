# dfd_generator.py

def generate_dfd_text(dfd_entities, dfd_flows):
    output = "=== Entities ===\n"
    for e in dfd_entities:
        output += f"{e['type']}: {e['name']} (Boundary: {e['boundary']})\n"

    output += "\n=== Flows ===\n"
    for fl in dfd_flows:
        output += f"{fl['source']} -> {fl['destination']} [{fl['protocol']}:{fl['port']}]\n"

    return output
