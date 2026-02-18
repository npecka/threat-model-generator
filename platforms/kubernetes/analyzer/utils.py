# utils.py
import re

def sanitize_name(name):
    return re.sub(r'\W|^(?=\d)', '_', name)
