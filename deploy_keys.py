import argparse
import json
import requests
import sys
from pathlib import Path


args = argparse.ArgumentParser()
args.add_argument("keys", type=Path)
args = args.parse_args()

if not args.keys.exists():
    print("Error: keys file doesn't exist")
    sys.exit(1)

data = json.loads(args.keys.read_text())

request = {
    "journalist_key": data["signing"]["public"],
    "journalist_sig": data["signing"]["signature"],
    "journalist_fetching_key": data["encrypting"]["public"],
    "journalist_fetching_sig": data["encrypting"]["signature"],
}

res = requests.post("http://127.0.0.1:8000/journalist", json=request)
res.raise_for_status()
print(res.json())
print("Journalist registered!")
