# localfw

Generic firewall script for end-hosts or NAT gateways
Initially based on "http://www.linuxhelp.net/guides/iptables/"

Provides an easy access to allow local or forwarded services via preconfigured "tuples"

	LOCAL_TUPLES="T22 53 U67S U68S 10.100.0.0/16;T443 !192.168.0.0/16"

Note that these remote forwards will not be applied if an internal non-default route is not found.

	REMOTE_TUPLES="10.1.1.51;T25 10.1.1.51;53 10.1.1.50;2300-2400"

TUPLES are port, IP, or IP+port pairs used to define the firewall rules.

* Use the T prefix for tcp-only, U for udp only.  No prefix means both TCP and UDP  
* You can specify 'I' for ICMP, and then the 'port' become the ICMP type.  
* You cannot mix ICMP and TCP/UDP on the same tuple - use separate entries.  
* A suffix of 'S' will enforce the equivalent source port, which is great for DHCP rules
* IPv6 addresses work here as well:  2000::beef:cafe;T25  
* Destination forwarding can also specify ranges of ports:  U32768-32999
* You can specify multiple-same ports or hosts for multiple tuple-rules  
* Prefix the tuple with an exclaimation point to negate it (turn into deny)  


Note: It's easy to conflict local services with forwarded ports, so be careful.
