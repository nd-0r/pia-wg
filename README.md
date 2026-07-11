# Private Internet Access Wireguard Configuration Generator

This project was forked from https://github.com/djtroyal/pia-wg, which was forked from https://github.com/hsand/pia-wg.

pia-wg is a Python-based WireGuard configuration utility for Private Internet Access. 

This fork has been modified in the following ways from djtroyal's:

- Uses the v2 auth endpoint POST form at `www.privateinternetaccess.com`, as recommended [here](https://github.com/pia-foss/manual-connections/tree/master).
- Avoids the issue with PIA's CA cert not adhering to RFC 5280, as discussed [here](https://github.com/pia-foss/manual-connections/tree/master).
- Uses the latest PIA serverlist ("v7" as of 20260710).
- Some ergonomics, like a CLI interface, Jinja templating, and a `pyproject.toml` for use with UV.

# Installation

## Linux

1. Install dependencies, clone pia-wg project, and create a virtual Python environment:

```
sudo apt install git wireguard-tools openresolv
python3 -m pip install uv
git clone https://github.com/nd-0r/pia-wg <directory>
cd <directory>/pia-wg
uv venv
source .venv/bin/activate
uv sync
```

### Running the Utility

- Activate the venv and run the Python script, providing the correct arguments:

```
source .venv/bin/activate
python3 main.py <...args>
```

This will output the config to stdout or the specified output file.

Copy the generated config file to `/etc/wireguard/` and start the interface, e.g.:

```
sudo cp PIA-wg.conf /etc/wireguard/wg0.conf
sudo wg-quick up wg0
```

You can shut down the interface with `sudo wg-quick down wg0`

## Check if it's Working

- If you have `curl` installed, you can check to see if your WAN (public) IP address has changed from your ISP-provided one using the command line:
```
curl icanhazip.com
```

- And/or visit https://dnsleaktest.com/ to make sure you see a strange new IP and check for DNS leaks.

