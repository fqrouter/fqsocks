import os
import json

DEFAULT_CONFIG = {
    'china_shortcut_enabled': True,
    'direct_access_enabled': True,
    'youtube_scrambler_enabled': True,
    'tcp_scrambler_enabled': True,
    'access_check_enabled': True,
    'http_manager': {
        'enabled': True,
        'ip': '',
        'port': 2515
    },
    'http_gateway': {
        'enabled': False,
        'ip': '',
        'port': 2516
    },
    'wifi_repeater': {
        'ssid': 'fqrouter',
        'password': '12345678'
    }
}

path = ''


def read_config():
    if not path:
        return dict(DEFAULT_CONFIG)
    if os.path.exists(path):
        with open(path) as f:
            config = dict(DEFAULT_CONFIG)
            config.update(json.loads(f.read()))
            return config
    else:
        return dict(DEFAULT_CONFIG)


def update_config(apply=None, **kwargs):
    config = read_config()
    config.update(kwargs)
    if apply:
        apply(config)
    with open(path, 'w') as f:
        f.write(json.dumps(config))
