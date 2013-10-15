import os
import json
from uuid import uuid4

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
    'dns_server': {
        'enabled': False,
        'ip': '',
        'port': 12345
    },
    'tcp_gateway': {
        'enabled': False,
        'ip': '',
        'port': 12345
    },
    'wifi_repeater': {
        'ssid': 'fqrouter',
        'password': '12345678'
    },
    'public_servers': {
        'source': 'proxies.fqrouter.com',
        'goagent_enabled': True,
        'ss_enabled': True
    },
    'private_servers': {}
}

cli_args = None


def read_config():
    config = _read_config()
    config['log_level'] = cli_args.log_level
    config['log_file'] = cli_args.log_file
    config['ip_command'] = cli_args.ip_command
    config['ifconfig_command'] = cli_args.ifconfig_command
    config['outbound_ip'] = cli_args.outbound_ip
    config['google_host'] = cli_args.google_host
    for props in cli_args.proxy:
        props = props.split(',')
        prop_dict = dict(p.split('=') for p in props[1:])
        n = int(prop_dict.pop('n', 0))
        add_proxy(config, props[0], n, **prop_dict)
    if cli_args.china_shortcut_enabled is not None:
        config['china_shortcut_enabled'] = cli_args.china_shortcut_enabled
    if cli_args.direct_access_enabled is not None:
        config['direct_access_enabled'] = cli_args.direct_access_enabled
    if cli_args.youtube_scrambler_enabled is not None:
        config['youtube_scrambler_enabled'] = cli_args.youtube_scrambler_enabled
    if cli_args.tcp_scrambler_enabled is not None:
        config['tcp_scrambler_enabled'] = cli_args.tcp_scrambler_enabled
    if cli_args.access_check_enabled is not None:
        config['access_check_enabled'] = cli_args.access_check_enabled
    if cli_args.no_http_manager:
        config['http_manager']['enabled'] = False
    if cli_args.http_manager_listen:
        config['http_manager']['enabled'] = True
        config['http_manager']['ip'], config['http_manager']['port'] = parse_ip_colon_port(cli_args.http_manager_listen)
    if cli_args.http_gateway_listen:
        config['http_gateway']['enabled'] = True
        config['http_gateway']['ip'], config['http_gateway']['port'] = parse_ip_colon_port(cli_args.http_gateway_listen)
    if cli_args.dns_server_listen:
        config['dns_server']['enabled'] = True
        config['dns_server']['ip'], config['dns_server']['port'] = parse_ip_colon_port(cli_args.dns_server_listen)
    if cli_args.tcp_gateway_listen:
        config['tcp_gateway']['enabled'] = True
        config['tcp_gateway']['ip'], config['tcp_gateway']['port'] = parse_ip_colon_port(cli_args.tcp_gateway_listen)
    return config


def add_proxy(config, proxy_type, n=0, **kwargs):
    if n:
        for i in range(1, 1 + n):
            private_server = {k: v.replace('#n#', str(i)) for k, v in kwargs.items()}
            private_server['proxy_type'] = proxy_type
            config['private_servers'][str(uuid4())] = private_server
    else:
        kwargs['proxy_type'] = proxy_type
        config['private_servers'][str(uuid4())] = kwargs


def _read_config():
    if not cli_args:
        return dict(DEFAULT_CONFIG)
    if os.path.exists(cli_args.config_file):
        with open(cli_args.config_file) as f:
            config = dict(DEFAULT_CONFIG)
            content = f.read()
            if content:
                config.update(json.loads(content))
            return config
    else:
        return dict(DEFAULT_CONFIG)


def update_config(apply=None, **kwargs):
    if not cli_args:
        return
    config = _read_config()
    config.update(kwargs)
    if apply:
        apply(config)
    with open(cli_args.config_file, 'w') as f:
        f.write(json.dumps(config))


def parse_ip_colon_port(ip_colon_port):
    if not isinstance(ip_colon_port, basestring):
        return ip_colon_port
    if ':' in ip_colon_port:
        server_ip, server_port = ip_colon_port.split(':')
        server_port = int(server_port)
    else:
        server_ip = ip_colon_port
        server_port = 53
    return '' if '*' == server_ip else server_ip, server_port