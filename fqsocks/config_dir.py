import os
import json

CONFIG_DIR = ''


def read_fqrouter_config():
    if not CONFIG_DIR:
        return {}
    path = os.path.join(CONFIG_DIR, 'fqrouter.json')
    if os.path.exists(path):
        with open(path) as f:
            return json.loads(f.read())


def update_fqrouter_config(**kwargs):
    if not CONFIG_DIR:
        return {}
    path = os.path.join(CONFIG_DIR, 'fqrouter.json')
    if os.path.exists(path):
        with open(path) as f:
            config = json.loads(f.read())
    config.update(kwargs)
    with open(path, 'w') as f:
        f.write(json.dumps(config))
