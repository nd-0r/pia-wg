from piawg import Piawg
import os
import sys
import argparse
from jinja2 import Environment, PackageLoader
from pathlib import Path

USER_ENVIRON='PIA_USER'
PASS_ENVIRON='PIA_PASS'
REGION_ENVIRON='PIA_REGION'
TEMPLATE_SUFFIX='.conf.j2'
DEFAULT_CA_CERT_URL='https://raw.githubusercontent.com/pia-foss/manual-connections/refs/heads/master/ca.rsa.4096.crt'
SYSTEMD_NETDEV='50-wg0.netdev'
SYSTEMD_NETWORK='50-wg0.network'

def main():
    template_loader = PackageLoader('piawg')
    template_options = [ 'container', 'default', 'systemd' ]

    parser = argparse.ArgumentParser(
        prog='pia-wg',
        description='pia-wg is a Python-based WireGuard configuration utility for Private Internet Access.'
    )

    parser.add_argument('-u', '--username', default=os.environ.get(USER_ENVIRON, None), help=f'PIA username. Default ${USER_ENVIRON}')
    parser.add_argument('-p', '--password', default=os.environ.get(PASS_ENVIRON, None), help=f'PIA password. Default ${PASS_ENVIRON}')
    parser.add_argument('--region', default=os.environ.get(REGION_ENVIRON, None), help=f'PIA region. Default ${REGION_ENVIRON}')
    parser.add_argument('-c', '--config', default='default', choices=template_options)
    parser.add_argument('-o', '--output', default='-')
    parser.add_argument('--systemd', default=Path("/etc/systemd/network/"), type=Path, help='Path to folder for installing systemd units for use with "systemd" config mode')
    parser.add_argument('--ca_cert', default=None, type=Path, help='Path to CA certificate file for verification VPN server identity')

    args = parser.parse_args()

    if args.username is None:
        parser.error("Username is required")

    if args.password is None:
        parser.error("Password is required")

    if args.region is None:
        parser.error("Region is required")

    pia = Piawg(args.ca_cert if args.ca_cert is not None else DEFAULT_CA_CERT_URL)

    # Generate public and private key pair
    pia.generate_keys()

    # Select region
    pia.set_region(args.region)

    pia.get_token(args.username, args.password)
    print("Login successful!", file=sys.stderr)

    # Authenticate with PIA Wireguard REST API
    pia.addkey()

    if args.config == 'systemd':
        with open(os.path.join(args.systemd, SYSTEMD_NETDEV), 'w') as f:
            template = Environment(loader=template_loader).get_template('systemd-networkd/' + SYSTEMD_NETDEV + '.j2')
            rendered_bytes = template.render(connection=pia.connection, privatekey=pia.privatekey).encode(encoding='utf-8')
            f.buffer.write(rendered_bytes)
        with open(os.path.join(args.systemd, SYSTEMD_NETWORK), 'w') as f:
            template = Environment(loader=template_loader).get_template('systemd-networkd/' + SYSTEMD_NETWORK + '.j2')
            rendered_bytes = template.render(connection=pia.connection, privatekey=pia.privatekey).encode(encoding='utf-8')
            f.buffer.write(rendered_bytes)
    else:
        outfile = sys.stdout if args.output == '-' else open(Path(args.output))

        try:
            template = Environment(loader=template_loader).get_template(args.config + TEMPLATE_SUFFIX)
            rendered_bytes = template.render(connection=pia.connection, privatekey=pia.privatekey).encode(encoding='utf-8')
            outfile.buffer.write(rendered_bytes)
        finally:
            if args.output != '-':
                outfile.close()
