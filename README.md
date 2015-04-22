localfw

Generic firewall script for end-hosts or NAT gateways

based on "http://www.linuxhelp.net/guides/iptables/"  but very mucked up.

Provides an easy access to allow local or forwarded services

such as:

LOCAL_SERVICES="22 80 443"

# Note that these remote forwards will not be applied if an internal non-default route is not found.

TUPLES="10.1.1.51;T25 10.1.1.51;53 10.1.1.50;2300-2400"


