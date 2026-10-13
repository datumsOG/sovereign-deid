import json
from pathlib import Path

FIX = Path(__file__).parent

def load(name):
    return json.loads((FIX / f"{name}.json").read_text())
