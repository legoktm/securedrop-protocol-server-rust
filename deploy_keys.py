import argparse
import json
import requests
import sys
from pathlib import Path


args = argparse.ArgumentParser()
args.add_argument("keys", type=Path)
args = args.parse_args()

if not args.keys.exists():
    print("Error: keys folder doesn't exist")
    sys.exit(1)

data = json.loads((args.keys / "main.key").read_text())

request = {
    "journalist_key": data["signing"]["public"],
    "journalist_sig": data["signing"]["signature"],
    "journalist_fetching_key": data["encrypting"]["public"],
    "journalist_fetching_sig": data["encrypting"]["signature"],
}

res = requests.post("http://127.0.0.1:8000/journalist", json=request)
res.raise_for_status()
print(res.json())
id = res.json()["id"]
print(f"Journalist registered as id #{id}!")
# Register the ephemeral keys now
register = []
for ephem in args.keys.glob("ephemeral*.key"):
    data = json.loads(ephem.read_text())
    register.append({
        "key": data["public"],
        "signature": data["signature"],
    })

res = requests.post(f"http://127.0.0.1:8000/journalist/{id}/ephemeral", json=register)
res.raise_for_status()
print(res.json())
print("Registered ephemeral keys!")
