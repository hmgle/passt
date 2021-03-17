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
			printf "abcd\n" && break
		fi
		__c=$((__c + 1))
	done
	unset IFS
}

ndp_setup() {
	sysctl -w net.ipv6.conf.all.proxy_ndp=1
	ip -6 neigh add proxy "${1}" dev "$(ipv6_dev)"
}

ip netns del passt 2>/dev/null || :
ip link del veth_passt 2>/dev/null || :
ip netns add passt
ip link add veth_passt up netns passt type veth peer name veth_passt
ip link set dev veth_passt up


ip -n passt addr add 192.0.2.2/24 dev veth_passt
ip addr add 192.0.2.1/24 dev veth_passt
ip -n passt route add default via 192.0.2.1

sysctl -w net.ipv4.ip_forward=1
nft delete table passt_nat 2>/dev/null || :
nft add table passt_nat
nft 'add chain passt_nat postrouting { type nat hook postrouting priority -100 ; }'
nft add rule passt_nat postrouting ip saddr 192.0.2.2 masquerade

ipv6_addr="$(ipv6_devaddr "$(ipv6_dev)")"
ipv6_passt="$(ipv6_mangle "${ipv6_addr}")"
ndp_setup "${ipv6_passt}"
ip -n passt addr add "${ipv6_passt}/$(ipv6_mask "${ipv6_addr}")" dev veth_passt
ip addr add "${ipv6_addr}" dev veth_passt
passt_ll="$(ipv6_ll_addr "veth_passt")"
main_ll="$(get_token "link/ether" $(ip -o li sh veth_passt))"
ip neigh add "${passt_ll%%/*}" dev veth_passt lladdr "${main_ll}"
ip -n passt route add default via "${passt_ll%%/*}" dev veth_passt

sysctl -w net.ipv6.conf.all.forwarding=1


ethtool -K veth_passt tx off
ip netns exec passt ethtool -K veth_passt tx off
ip netns exec passt sysctl -w net.ipv4.ping_group_range="0 2147483647"
ulimit -n 300000


ip netns exec passt ./passt
