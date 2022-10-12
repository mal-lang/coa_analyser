import json
import os

def read_json_file(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as json_file:
            return json.load(json_file)
    else:
        return {}


def write_json_file(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

