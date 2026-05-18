import csv
import json
from io import StringIO, BytesIO

def handle_uploaded_file(filename, content):
    if filename.endswith('.csv'):
        return parse_csv(content)
    elif filename.endswith('.json'):
        return parse_json(content)
    else:
        raise ValueError("Unsupported file type. Only .csv and .json are allowed.")

def parse_csv(content):
    try:
        # Handle both bytes and str
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        f = StringIO(content)
        reader = csv.DictReader(f)
        return [row for row in reader]
    except Exception as e:
        raise ValueError(f"CSV parsing error: {e}")

def parse_json(content):
    try:
        # Handle both bytes and str
        if isinstance(content, bytes):
            content = content.decode('utf-8')
        return json.loads(content)
    except Exception as e:
        raise ValueError(f"JSON parsing error: {e}")
