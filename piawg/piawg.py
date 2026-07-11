import requests
import json
from requests_toolbelt.adapters.host_header_ssl import HostHeaderSSLAdapter
import subprocess
import urllib.parse
from pathlib import Path
import ssl
import tempfile

# Use newest version of PIA serverlist ("v6" as of 20260710)
PIA_SERVERLIST_URL='https://serverlist.piaservers.net/vpninfo/servers/v7'

# PIA uses the CN attribute for certificates they issue themselves.
# This will be deprecated by urllib3 at some point in the future, and generates a warning (that we ignore).
# urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)

# This class serves to disable strict SSL certificate verification because PIA CA cert does not adhere to RFC 5280.
# See https://github.com/pia-foss/manual-connections/issues/213 and https://runebook.dev/en/docs/python/library/ssl/ssl.VERIFY_X509_STRICT
class NonstrictHostHeaderSSLAdapter(HostHeaderSSLAdapter):
    def init_poolmanager(self, *args, **kwargs):
        custom_context = ssl.create_default_context()
        custom_context.verify_flags &= ~ssl.VERIFY_X509_STRICT
        kwargs['ssl_context'] = custom_context
        return super(NonstrictHostHeaderSSLAdapter, self).init_poolmanager(*args, **kwargs)

class Piawg:
    def __init__(self, ca_cert_path: Path | str):
        self.server_list = {}
        self.get_server_list()
        self.ca_cert_bytes = None
        self.get_ca_cert(ca_cert_path)
        self.region = None
        self.token = None
        self.publickey = None
        self.privatekey = None
        self.connection = None

    def get_server_list(self):
        r = requests.get(PIA_SERVERLIST_URL)
        # Only process first line of response, there's some base64 data at the end we're ignoring
        data = json.loads(r.text.splitlines()[0])
        for server in data['regions']:
            self.server_list[server['name']] = server

    def get_ca_cert(self, ca_cert_path: Path | str):
        if isinstance(ca_cert_path, Path):
            self.ca_cert_bytes = ca_cert_path.read_bytes()
        else:
            res = requests.get(ca_cert_path)
            res.raise_for_status()
            self.ca_cert_bytes = res.content

    def set_region(self, region_name):
        self.region = region_name

    def get_token(self, username, password):
        # See https://github.com/pia-foss/manual-connections/blob/master/get_token.sh
        r = requests.post("https://www.privateinternetaccess.com/api/client/v2/token",
                  data={ u'username': username, u'password': password })
        r.raise_for_status()

        data = r.json()
        self.token = data['token']

    def generate_keys(self):
        self.privatekey = subprocess.run(['wg', 'genkey'], stdout=subprocess.PIPE, encoding="utf-8").stdout.strip()
        self.publickey = subprocess.run(['wg', 'pubkey'], input=self.privatekey, stdout=subprocess.PIPE,
                                        encoding="utf-8").stdout.strip()

    def addkey(self):
        # Get common name and IP address for wireguard endpoint in region
        # See https://github.com/pia-foss/manual-connections/blob/master/connect_to_wireguard_with_token.sh
        cn = self.server_list[self.region]['servers']['wg'][0]['cn']
        ip = self.server_list[self.region]['servers']['wg'][0]['ip']

        s = requests.Session()
        s.mount('https://', NonstrictHostHeaderSSLAdapter())

        if not self.ca_cert_bytes:
            raise RuntimeError('`get_ca_cert` must be called before `addkey`')

        with tempfile.NamedTemporaryFile(delete=True) as f:
            # Use the custom CA key
            f.write(self.ca_cert_bytes)
            f.flush()
            s.verify = f.name

            if not self.token or not self.publickey:
                raise RuntimeError('`get_token` and `generate_keys` must be called before `addkey`')

            token = urllib.parse.quote(self.token)
            pubkey = urllib.parse.quote(self.publickey)

            r = s.get(f'https://{ip}:1337/addKey?pt={token}&pubkey={pubkey}', headers={"Host": cn})

            r.raise_for_status()

            data = r.json()

            if data['status'] != 'OK':
                raise RuntimeError(f'Unexpected result status from `addkey`: {data['status']}')

            self.connection = data
