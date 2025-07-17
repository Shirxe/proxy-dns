# Proxy DNS

## Configuration

The project uses a configuration file located at `config/config.toml` with the main settings:

```toml
# google dns:       8.8.8.8
# cloudflare dns:   1.1.1.1
dns_server = "8.8.8.8"

# FORMERR   (1):    The DNS query had a format error.
# SERVFAIL  (2):    The DNS server failed to process the query.
# NXDOMAIN  (3):    The domain name does not exist.
# NOTIMP    (4):    The requested function is not implemented.
# REFUSED   (5):    The server refused to answer the query.
# YXDOMAIN  (6):    The name that should not exist, does exist.
# YXRRSET   (7):    The RRset that should not exist, does exist.
# NXRRSET   (8):    The RRset that should exist, does not exist.
# NOTAUTH   (9):    Server is not authoritative for the zone.
# NOTZONE   (10):   Name not in zone. 
blacklist_response_code = 2 # SERVFAIL

# Support examples:
# *.example.*
# api.example
# api.example.*
# api.example.dp.*
blacklist = ["*.mysite.dp.*", "google.com"]
```


## Build

```bash
git clone https://github.com/Shirxe/proxy-dns
cd proxy-dns/
git submodule update --init --recursive
mkdir build
cd build
cmake ..
cmake --build .
```

## Testing

You can configure testing parameters in the `test/test.sh` script:

```bash
# Port that will be used by UDP server
PORT=9898

# A - IPv4
# AAAA - IPv6
FLAGS=AAAA

DOMAINS=(
    "mysite.dp"
    "mysite.dp.ua"
    "api.mysite.dp"
    "api.mysite.dp.ua"
    "api.mysite.dp.ua.xd"
    "subdomain.api.mysite.dp.ua.xd"
    "google.com"
    "api.google.com"
    "youtube.com"
)
```

# Execute test

Before starting the tests, make sure that **the project is built** and that the **"dig"** utility is installed:
```bash
sudo apt install dnsutils
sudo pacman -S bind
```

```bash
cd test/
chmod +x test.sh
./test.sh
```
