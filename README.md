# FlexibleFirewall

Generic firewall script for end-hosts or NAT gateways
Initially based on "http://www.linuxhelp.net/guides/iptables/"

Provides an easy access to allow local or forwarded services via pre-configured "tuples"

	LOCAL_TUPLES="T22 53 U67 U68 P41 @1714 @5353 fe80::/10 ff00::/8 10.100.0.0/16;T443 !192.168.0.0/16"

Note that these remote forwards will not be applied if an internal non-default route is not found.

	REMOTE_TUPLES="10.1.1.51;T25 10.1.1.51;53 10.1.1.50;2300-2400"

TUPLES are port, IP, or IP+port pairs used to define the firewall rules.

* Use the T prefix for tcp-only, U for udp only.  No prefix means both TCP and UDP  
* You can specify 'I' for ICMP, and then the 'port' become the ICMP type.  
* You cannot mix ICMP and TCP/UDP on the same tuple - use separate entries.  
* A suffix of 'S' will enforce the equivalent source port, which is great for DHCP rules
* IPv6 addresses work here as well:  2000::beef:cafe;T25  
* Destination forwarding can also specify ranges of ports:  U32768-32999
* A prefix of 'P' will allow you to permit/deny specific IPv4 protocols (such as P41 for 6-in-4 tunneling)
* You can specify multiple-same ports or hosts for multiple tuple-rules  
* Prefix the tuple with an exclamation point to negate it (turn into deny)  
* Prefix the tuple with an 'at-sign' instead of '!' to silently deny


Note: It's easy to conflict local services with forwarded ports, so be careful.


# Install (systemd)

* put a copy in /usr/local/sbin/
* chmod +x /usr/local/sbin/FlexibleFirewall
* put a copy of the systemd unit file (FlexibleFirewall.service) in /etc/systemd/system/ and "systemctl daemon-reload"
* edit the top of the script for your local rules
*  OR (preferred) create /etc/default/FlexibleFirewall  and put your rules there.
* give it a run (systemctl start FlexibleFirewall )

# Install (sysv init)

* put a copy in /etc/init.d
* chmod +x /etc/init.d/FlexibleFirewall
* create symlinks for startup/shutdown in the appropriate /etc/rcX.d  (update-rc.d FlexibleFirewall defaults)
* edit the top of the script for your local rules
*  OR (preferred) create /etc/default/FlexibleFirewall  and put your rules there.
* give it a run (service FlexibleFirewall start )

