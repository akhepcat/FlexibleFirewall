#!/bin/bash
# Initially based on "http://www.linuxhelp.net/guides/iptables/"
#    for the generic IPtables rules, as it had some nice defaults

# TUPLES are port, IP, or IP+port pairs used to define the firewall rules.
# use the T prefix for tcp-only, U for udp only.  No prefix means both TCP and UDP
# You can specific 'I' for ICMP, and then the 'port' become the ICMP type.
#  You cannot mix ICMP and TCP/UDP on the same tuple - use separate entries.
# a suffix of 'S' will enforce the equivalent source port, which is great for DHCP rules
#
# IPv6 addresses should work here as well:  2000::beef:cafe;T25
# You can specify multiple-same ports or hosts for multiple rules
# prefix with an exclaimation point to negate the tuple (turn into deny)
#
# space separated tuples to allow local services like ssh(22), smtp(25), http(80), https(443)
# note that it's easy to conflict local services with forwarded ports, so be careful.

# Apply a basic ruleset for an endpoint: Only dhcp, dns, and ssh are allowed
LOCAL_TUPLES="T22 53 U67S U68S"     # other valid tuples: "10.100.0.0/16;T443 !192.168.0.0/16"

# 1 to enable IP forwarding/NAT,  0 disables, by default
FORWARDING=0

# If forwarding is enabled, and you would like to forward specific
# ports to other machines on your home network, edit the variable below.
# They are currently set up to forward port 25 & 53 (Mail & DNS) to the example 10.1.1.51.
# Anything incoming over your $EXT_4IF through your gateway will 
# be automatically redirected invisibly to port 25 & 53 on 10.1.1.51
#
# we don't currently support ICMP forwarding, because that's weird.
#
# These will automatically generate ACCEPT rules for outbound traffic as well
# Note that these will not be applied if an internal non-default route is not found.
REMOTE_TUPLES="10.1.1.51;T25 10.1.1.51;53 10.1.1.50;2300-2400"


###########################################
DEBUG="false"	# null-string disables, non-null string enables

# The location of the ipXtables binaries file on your system.
# We try to set up equivalent IPv4 and IPv6 rules, if you've got them.
test -x /sbin/iptables${DEBUG} && IP4T="/sbin/iptables" || IP4T="ignore4"
test -x /sbin/ip6tables${DEBUG} && IP6T="/sbin/ip6tables" || IP6T="ignore6"

# The Network Interface you will be protecting. 
# this will automagically configure for your external default interface
EXT_4IF="$(awk 'BEGIN { IGNORECASE=1 } /^[a-z0-9]+[ \t]+00000000/ { print $1; exit }' /proc/net/route)"
EXT_6IF="$(awk 'BEGIN { IGNORECASE=1 } /^0+ 00 0+ 00/ && !/ffffffff/ { print $10; exit }' /proc/net/ipv6_route)"

cmd=${1:-help}
cmd=${cmd,,}

FAIL2BAN=0

ignore4() {
	args="$*"
	
	[[ -n "$DEBUG" ]] && echo "DEBUG: iptables ${args}"
}

ignore6() {
	args="$*"
	
	[[ -n "$DEBUG" ]] && echo "DEBUG: ip6tables ${args}"
}

tuple_forward() {
	for SERVICE in $REMOTE_TUPLES
	do
		DPORT=""

		ACTION="ACCEPT"
		[[ -z "${SERVICE##*!*}" ]] && ACTION="DENY" && SERVICE=${SERVICE//!/}
		
		if [ -z "${SERVICE##*;*}" ]
		then
			# address + service tuple
			DPORT=${SERVICE#*;}
			SERVICE="${SERVICE%;*}"
		fi
		# fall through to parse the rest of the service.
		if [ -z "${SERVICE##*/*}" -o -z "${SERVICE##*:*}" -o -z "${SERVICE##*.*}" ]
		then
			# bare IP (v4/v6) 'any/any'  tuple, because no trailing service
			HOST=${SERVICE}
		else
			# it doesn't parse to an IP, so it's a port
			DPORT=${SERVICE}
		fi 

		UDP=0; TCP=0
		if [ -n "$DPORT" ]
		then
			[[ -z "${DPORT##T*}" ]] && TCP=1
			[[ -z "${DPORT##U*}" ]] && UDP=1

			if [ -n "${DPORT##U*}" -a -n "${DPORT##T*}" ]; then TCP=1; UDP=1; fi

			DPORT=${DPORT//[TUI]/}

			if [ -z "${DPORT##*-*}" ]
			then
				LPORT="--dport ${DPORT//-/:}"
				DPORT=""
			else
				LPORT="--dport $DPORT"
				DPORT=":${DPORT}"
			fi
		fi
	
		EXT_IF=$EXT_4IF
		if [ -z "${HOST##*:*}" ]
		then
			EXT_IF=$EXT_6IF
			FWSTACK=$IP6T
		else
			FWSTACK=$IP4T
		fi

		VALID=$(ip -o route get ${HOST})
		if [ -n "${VALID##*$EXT_IF*}" -o -n "$DEBUG" ]
		then
			[[ $TCP -eq 1 ]] && $FWSTACK -t nat -A PREROUTING -i $EXT_IF -p tcp ${LPORT} -j DNAT --to ${HOST}${DPORT}
			[[ $UDP -eq 1 ]] && $FWSTACK -t nat -A PREROUTING -i $EXT_IF -p udp ${LPORT} -j DNAT --to ${HOST}${DPORT}
		fi
	
	done
}

tuple_locals() {
	for SERVICE in $LOCAL_TUPLES
	do
		DPORT=""

		ACTION="ACCEPT"
		[[ -z "${SERVICE##*!*}" ]] && ACTION="DENY" && SERVICE=${SERVICE//!/}
		
		if [ -z "${SERVICE##*;*}" ]
		then
			# address + service tuple
			DPORT=${SERVICE#*;}
			SERVICE="${SERVICE%;*}"
		fi
		# fall through to parse the rest of the service.
		if [ -z "${SERVICE##*/*}" -o -z "${SERVICE##*:*}" -o -z "${SERVICE##*.*}" ]
		then
			# bare IP (v4/v6) 'any/any'  tuple, because no trailing service
			SOURCE="-s ${SERVICE}"
		else
			# it doesn't parse to an IP, so it's a port
			DPORT=${SERVICE}
		fi

		UDP=0; TCP=0; SPORT=""
		if [ -n "$DPORT" ]
		then
			[[ -z "${DPORT%%*S}" ]] && SPORT="--sport ${DPORT//S/}" && DPORT=${DPORT//S/}
			[[ -z "${DPORT##T*}" ]] && TCP=1 && DPORT="--dport $DPORT"
			[[ -z "${DPORT##U*}" ]] && UDP=1 && DPORT="--dport $DPORT"
			[[ -z "${DPORT##I*}" ]] && ICMP=1 && DPORT="--icmp-type $DPORT"

			if [ -n "${DPORT##*U*}" -a -n "${DPORT##*T*}" -a -n "${DPORT##*I*}" ]; then TCP=1; UDP=1; fi

			DPORT=${DPORT//[UIT]/}
		else
			# DPORT is null, so there's no service, so assume all protos
			TCP=1
			UDP=1
			ICMP=1
		fi

		EXT_IF=$EXT_4IF
		if [ -z "${HOST##*:*}" ]
		then
			EXT_IF=$EXT_6IF
			FWSTACK=$IP6T
		else
			FWSTACK=$IP4T
		fi

		[[ $TCP -eq 1 ]] && $FWSTACK -A INPUT -i $EXT_IF ${SOURCE} -p tcp $DPORT $SPORT -j ${ACTION}
		[[ $UDP -eq 1 ]] && $FWSTACK -A INPUT -i $EXT_IF ${SOURCE} -p udp $DPORT $SPORT -j ${ACTION}
		[[ $ICMP -eq 1 ]] && $FWSTACK -A INPUT -i $EXT_IF ${SOURCE} -p icmp $DPORT -j ${ACTION}
	done
}

tuple_accept() {
	for ALLOW in $REMOTE_TUPLES
	do
		HOST=${ALLOW%;*}
	
		EXT_IF=$EXT_4IF
		if [ -z "${HOST##*:*}" ]
		then
			EXT_IF=$EXT_6IF
			FWSTACK=$IP6T
			DEST="::0"
		else
			FWSTACK=$IP4T
			DEST="0/0"
		fi

		if [ -n "${HOST}" ]
		then
			VALID=$(ip -o route get ${HOST})
			[[ -n "${VALID##*$EXT_IF*}" ]] && $FWSTACK -A ALLOW -s ${HOST} -d ${DEST}  -p all -j ACCEPT
		fi
	done
}

stop() {
	# The following rules will clear out any existing firewall rules, 
	# and any chains that might have been created.
	for FWSTACK in $IP4T $IP6T
	do
		$FWSTACK -F
		$FWSTACK -F INPUT
		$FWSTACK -F OUTPUT
		$FWSTACK -F FORWARD
		$FWSTACK -F -t mangle
		$FWSTACK -F -t nat
		$FWSTACK -X
	done
}

forwarding() {
# The following line below enables IP forwarding and thus 
# by extension, NAT. Turn this on if you're going to be 
# doing NAT or IP Masquerading.

	STATE=0
	[[ "$1" = "start" ]] && STATE=1
	
	if [ $FORWARDING -gt 0 ]
	then
		[[ -n "${IP4T##*ignore*}" ]] && echo ${STATE} > /proc/sys/net/ipv4/ip_forward || echo "DEBUG: /proc/sys/net/ipv4/ip_forward not changed"
# no such IPv6 forwarding yet.  requires additional software support
# to provide IPv6 routing, subnet delegation, etc.
#		[[ -n "${IP6T##*ignore*}" ]] && echo ${STATE} > /proc/sys/net/ipv6/ip_forward || echo "DEBUG: /proc/sys/net/ipv6/ip_forward not changed"
	fi
}

start() {
# These will setup our policies.
	$IP4T -P INPUT DROP
	$IP6T -P INPUT DROP

	$IP4T -P OUTPUT ACCEPT
	$IP6T -P OUTPUT ACCEPT

	$IP4T -P FORWARD ACCEPT
	$IP6T -P FORWARD ACCEPT


if [ ${FORWARDING:-0} -gt 0 ]
then
	# this starts IP forwarding
	forwarding start

	# Source NAT everything heading out the $EXT_4IF (external) 
	# interface to be the given IP. If you have a dynamic IP 
	# address or a DHCP IP that changes semi-regularly, comment out 
	# the first line and uncomment the second line.
	#
	# Remember to change the ip address below to your static ip.
	#
	# $IP4T -t nat -A POSTROUTING -o $EXT_4IF -j SNAT --to 216.138.195.197
	# $IP6T -t nat -A POSTROUTING -o $EXT_6IF -j SNAT --to ${STATIC_EXT_IPv6}
	$IP4T -t nat -A POSTROUTING -o $EXT_4IF -j MASQUERADE
	$IP6T -t nat -A POSTROUTING -o $EXT_6IF -j MASQUERADE

	# This rule protects your fowarding rule.
	$IP4T -A FORWARD -i $EXT_4IF -m state --state NEW,INVALID -j DROP
	$IP6T -A FORWARD -i $EXT_6IF -m state --state NEW,INVALID -j DROP

	# set up the port forwards, if enabled
	tuple_forward
fi

# Now, our firewall chain. We use the limit commands to 
# cap the rate at which it alerts to 15 log messages per minute.
for FWSTACK in $IP4T $IP6T
do
	$FWSTACK -N firewall
	$FWSTACK -A firewall -m limit --limit 15/minute -j LOG --log-prefix Firewall:
	$FWSTACK -A firewall -j DROP

	# Now, our dropwall chain, for the final catchall filter.
	$FWSTACK -N dropwall
	$FWSTACK -A dropwall -m limit --limit 15/minute -j LOG --log-prefix Dropwall:
	$FWSTACK -A dropwall -j DROP

	# Our "hey, them's some bad tcp flags!" chain.
	$FWSTACK -N badflags
	$FWSTACK -A badflags -m limit --limit 15/minute -j LOG --log-prefix Badflags:
	$FWSTACK -A badflags -j DROP

	# And our silent logging chain.
	$FWSTACK -N silent
	$FWSTACK -A silent -j DROP
	
# Lets do some basic state-matching. This allows us 
# to accept related and established connections, so
# client-side things like ftp work properly, for example.
	$FWSTACK -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

	# This rule will accept connections from local machines.
	$FWSTACK -A INPUT -i lo -j ACCEPT
# Drop those nasty packets! These are all TCP flag 
# combinations that should never, ever occur in the
# wild. All of these are illegal combinations that 
# are used to attack a box in various ways, so we 
# just drop them and log them here.
	$FWSTACK -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j badflags
	$FWSTACK -A INPUT -p tcp --tcp-flags ALL ALL -j badflags
	$FWSTACK -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j badflags
	$FWSTACK -A INPUT -p tcp --tcp-flags ALL NONE -j badflags
	$FWSTACK -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j badflags
	$FWSTACK -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j badflags
done

# Build accept rules for all the internal tuples from the forwards
tuple_accept

# Drop icmp, but only after letting certain types through.
	$IP4T -A INPUT -p icmp --icmp-type 0 -j ACCEPT
	$IP4T -A INPUT -p icmp --icmp-type 3 -j ACCEPT
	$IP4T -A INPUT -p icmp --icmp-type 11 -j ACCEPT
	$IP4T -A INPUT -p icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT
	$IP4T -A INPUT -p icmp -j firewall

	$IP6T -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -m hl --hl-eq 255 -j ACCEPT
	$IP6T -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -m hl --hl-eq 255 -j ACCEPT
	$IP6T -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -m hl --hl-eq 255 -j ACCEPT
	$IP6T -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -m hl --hl-eq 255 -j ACCEPT
	$IP6T -A INPUT -p ipv6-icmp -j firewall

	tuple_locals

# Uncomment to drop port 137 netbios packets silently. 
# We don't like that netbios stuff, and it's way too 
# spammy with windows machines on the network.
for FWSTACK in $IP4T $IP6T
do
	$FWSTACK -A INPUT -p udp --sport 137 --dport 137 -j silent
	$FWSTACK -A INPUT -p udp --dport 5353 -j silent

# Our final trap. Everything on INPUT goes to the dropwall 
# so we don't get silent drops.
	$FWSTACK -A INPUT -j dropwall

	EXT_IF=$EXT_4IF
	[[ -z "${FWSTACK##*6*}" ]] && EXT_IF=$EXT_6IF

# Drop some specific outbound chatter
	$FWSTACK -A OUTPUT -o $EXT_IF -p udp --dport 5353 -j silent
	$FWSTACK -A OUTPUT -o $EXT_IF -p udp --dport 137 -j silent
	$FWSTACK -A OUTPUT -o $EXT_IF -p tcp --dport 445 -j silent
	$FWSTACK -A OUTPUT -o $EXT_IF -p udp --dport 445 -j silent
done

	IAM=$(id -ru)
	
	if [ 1 -eq ${IAM:-0} ]
	then
		if [ -x /usr/bin/fail2ban-client ]
		then
			service fail2ban restart
		else
			[[ -n "$LOCAL_TUPLES" ]] && echo "install fail2ban to prevent brute-forcing of your local IPv4 services" >&2
		fi
	else
		[[ -n "$DEBUG" ]] && echo "DEBUG: service fail2ban restart"
	fi
}

case ${cmd} in
        start) start
        	;;
        stop|flush|reset) stop
        	;;
        restart) stop; start
        	;;
        *) echo "$0 [stop|start|restart]"
        	;;
esac 
