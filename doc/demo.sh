#!/bin/sh -e
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# PASST - Plug A Simple Socket Transport
#
# demo.sh - Set up namespaces, addresses and routes to show PASST functionality
#
# Copyright (c) 2020-2021 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

get_token() {
	IFS=' 	'
	__next=0
	for __token in ${@}; do
		[ ${__next} -eq 2 ] && echo "${__token}" && return
		[ "${__token}" = "${1}" ] && __next=$((__next + 1))
	done
	unset IFS
}

ipv6_dev() { get_token "dev" $(ip -o -6 ro show default); }
ipv6_devaddr() { get_token "inet6" $(ip -o -6 ad sh dev "${1}" scope global); }
ipv6_ll_addr() { get_token "inet6" $(ip -o -6 ad sh dev "${1}" scope link); }
ipv6_mask() { echo ${1#*/}; }
ipv6_mangle() {
	IFS=':'
	__c=0
	for __16b in ${1%%/*}; do
		if [ ${__c} -lt 7 ]; then
			printf "${__16b}:"
		else
			printf "%04x\n" $((0xabc0 + ${2})) && break
		fi
		__c=$((__c + 1))
	done
	unset IFS
}

ndp_setup() {
	sysctl -w net.ipv6.conf.all.proxy_ndp=1
	ip -6 neigh add proxy "${1}" dev "$(ipv6_dev)"

	for i in `seq 1 63`; do
		__neigh="$(ipv6_mangle ${1} ${i})"
		if [ "${__neigh}" != "${1}" ]; then
			ip -6 neigh add proxy "${__neigh}" dev "${2}"
		fi
	done
}

ns_idx=0
for i in `seq 1 63`; do
	ns="passt_${i}"
	ns_idx=${i}

	busy=0
	for p in $(pidof passt); do
		[ "$(ip netns identify ${p})" = "${ns}" ] && busy=1 && break
	done
	[ ${busy} -eq 0 ] && break
done

[ ${busy} -ne 0 ] && echo "Couldn't create namespace" && exit 1

ip netns del "${ns}" 2>/dev/null || :
ip netns add "${ns}"
ip link del "veth_${ns}" 2>/dev/null || :
ip link add "veth_${ns}" up netns "${ns}" type veth peer name "veth_${ns}"
ip link set dev "veth_${ns}" up
ip link set dev "veth_${ns}" mtu 65535
ip -n "${ns}" link set dev "veth_${ns}" mtu 65535
ip -n "${ns}" link set dev lo up

ipv4_main="192.0.2.$(((ns_idx - 1) * 4 + 1))"
ipv4_ns="192.0.2.$(((ns_idx - 1) * 4 + 2))"

ip -n "${ns}" addr add "${ipv4_ns}/30" dev "veth_${ns}"
ip addr add "${ipv4_main}/30" dev "veth_${ns}"
ip -n "${ns}" route add default via "${ipv4_main}"

sysctl -w net.ipv4.ip_forward=1
nft delete table "${ns}_nat" 2>/dev/null || :
nft add table "${ns}_nat"
nft add chain "${ns}_nat" postrouting '{ type nat hook postrouting priority -100 ; }'
nft add rule "${ns}_nat" postrouting ip saddr "${ipv4_ns}" masquerade

ipv6_addr="$(ipv6_devaddr "$(ipv6_dev)")"
if [ -n "${ipv6_addr}" ]; then
	ipv6_passt="$(ipv6_mangle "${ipv6_addr}" ${ns_idx})"
	ndp_setup "${ipv6_passt}" "veth_${ns}"
	ip -n "${ns}" addr add "${ipv6_passt}/$(ipv6_mask "${ipv6_addr}")" dev "veth_${ns}"
	ip addr add "${ipv6_addr}" dev "veth_${ns}"
	ip route add "${ipv6_passt}" dev "veth_${ns}"
	passt_ll="$(ipv6_ll_addr "veth_${ns}")"
	main_ll="$(get_token "link/ether" $(ip -o li sh "veth_${ns}"))"
	ip neigh add "${passt_ll%%/*}" dev "veth_${ns}" lladdr "${main_ll}"
	ip -n "${ns}" route add default via "${passt_ll%%/*}" dev "veth_${ns}"

	sysctl -w net.ipv6.conf.all.forwarding=1
else
	ipv6_passt=
fi

ethtool -K "veth_${ns}" tx off
ip netns exec "${ns}" ethtool -K "veth_${ns}" tx off
ip netns exec "${ns}" sysctl -w net.ipv4.ping_group_range="0 2147483647"


sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=16777216
sysctl -w net.core.wmem_default=16777216
sysctl -w net.ipv4.tcp_rmem="16777216 131072 16777216"
sysctl -w net.ipv4.tcp_wmem="16777216 131072 16777216"

echo
echo "Namespace ${ns} set up, addresses:"
echo "    ${ipv4_ns}"
echo "    ${ipv6_passt}"
echo
echo "Starting passt..."
echo

ip netns exec "${ns}" ./passt | cat
