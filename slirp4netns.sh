#!/bin/sh -euf
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# slirp4netns.sh - Compatibility wrapper for pasta, behaving like slirp4netns(1)
#
# WARNING: Draft quality, not really tested
#
# Copyright (c) 2021-2022 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

PASTA_PID="$(mktemp)"
PASTA_OPTS="-q --ipv4-only -a 10.0.2.0 -n 24 -g 10.0.2.2 --dns-forward 10.0.2.3 -m 1500 --no-ndp --no-dhcpv6 --no-dhcp -P ${PASTA_PID}"
PASTA="$(command -v ./pasta || command -v pasta || :)"

API_SOCKET=
API_DIR="$(mktemp -d)"
PORTS_DIR="${API_DIR}/ports"
FIFO_REQ="${API_DIR}/req.fifo"
FIFO_RESP="${API_DIR}/resp.fifo"
PORT_ARGS=

USAGE_RET=1
NOTFOUND_RET=127

# add() - Add single option to $PASTA_OPTS
# $1:	Option name, with or without argument
add() {
	PASTA_OPTS="${PASTA_OPTS} ${1}"
}

# drop() - Drop one option (without argument) from $PASTA_OPTS
# $1:	Option name
drop() {
	old_opts="${PASTA_OPTS}"; PASTA_OPTS=
	for o in ${old_opts}; do [ "${o}" != "${1}" ] && add "${o}"; done
}

# sub() - Substitute option in $PASTA_OPTS, with or without argument
# $1:	Option name
# $2:	Option argument, can be empty
sub() {
	old_opts="${PASTA_OPTS}"; PASTA_OPTS=
	next=0
	for o in ${old_opts}; do
		if [ ${next} -eq 1 ]; then
			next=0; add "${1} ${2}"; shift; shift; continue
		fi

		for r in ${@}; do [ "${o}" = "${r}" ] && next=1 && break; done
		[ "${next}" -eq 0 ] && add "${o}"
	done
}

# xorshift() - pseudorandom permutation of 16-bit group
# $1:	16-bit value to shuffle
xorshift() {
	# Adaptation of Xorshift algorithm from:
	#   Marsaglia, G. (2003). Xorshift RNGs.
	#   Journal of Statistical Software, 8(14), 1 - 6.
	#   doi:http://dx.doi.org/10.18637/jss.v008.i14
	# with triplet (5, 3, 1), suitable for 16-bit ranges.
	n=${1}
	: $((n ^= n << 5))
	: $((n ^= n >> 3))
	: $((n ^= n << 1))
	echo ${n}
}

# opt() - Validate single option from getopts
# $1:	Option type
# $@:	Variable names to assign to
opt() {
	case "${1}" in
	u32)
		if ! printf "%i" "${OPTARG}" >/dev/null 2>&1 || \
		   [ "${OPTARG}" -lt 0 ]; then
			echo "${OPT} must be a non-negative integer"
			usage
		fi
		eval ${2}="${OPTARG}"
		;;
	mtu)
		if ! printf "%i" "${OPTARG}" >/dev/null 2>&1 || \
		   [ "${OPTARG}" -lt 0 ] || [ "${OPTARG}" -ge 65522 ]; then
			echo "MTU must be a positive integer (< 65522)"
			usage
		fi
		eval ${2}="${OPTARG}"
		;;
	str)
		eval ${2}="${OPTARG}"
		;;
	net4)
		addr="${OPTARG%/*}"
		mask="${OPTARG##*/}"

		{ [ -z "${mask}" ] || !printf "%i" "${mask}" >/dev/null 2>&1 \
		  || [ ${mask} -gt 32 ] || ${mask} -le 0 ]; } && usage

		expr "${addr}" :					      \
			'[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*$' \
			>/dev/null
		[ $? -ne 0 ] && usage

		ifs="${IFS}"; IFS='.'
		for q in ${addr}; do [ ${q} -gt 255 ] && usage; done
		IFS="${ifs}"

		eval ${2}="${addr}"
		eval ${3}="${mask}"
		;;
	esac
}

# start() - Start pasta
start() {
	${PASTA} ${PASTA_OPTS} ${PORT_ARGS} --netns ${ns_spec}
	[ ${RFD} -ne 0 ] && echo "1" >&${RFD} || :
}

# start() - Terminate pasta process
stop() {
	kill $(cat ${PASTA_PID})
}

# api_insert() - Handle add_hostfwd request, update PORT_ARGS
# $1:	Protocol, "tcp" or "udp"
# $2:	Host port
# $3:	Guest port
api_insert() {
	__id=
	__next_id=1	# slirp4netns starts from ID 1
	PORT_ARGS=

	for __entry in $(ls ${PORTS_DIR}); do
		PORT_ARGS="${PORT_ARGS} $(cat "${PORTS_DIR}/${__entry}")"

		if [ -z "${__id}" ] && [ ${__entry} -ne ${__next_id} ]; then
			__id=${__next_id}
		fi

		__next_id=$((__next_id + 1))
	done
	[ -z "${__id}" ] && __id=${__next_id}

	# Invalid ports are accepted by slirp4netns, store them as empty files.
	# Unknown protocols aren't.

	case ${1} in
	"tcp") opt="-t" ;;
	"udp") opt="-u" ;;
	*)
		echo '{"error":{"desc":"bad request: add_hostfwd: bad arguments.proto"}}'
		return
		;;
	esac

	if [ ${2} -ge 0 ] && [ ${2} -le 65535 ] && \
	   [ ${3} -ge 0 ] && [ ${3} -le 65535 ]; then
		echo "${opt} ${2}:${3}" > "${PORTS_DIR}/${__id}"
		PORT_ARGS="${PORT_ARGS} ${opt} ${2}:${3}"
	else
		:> "${PORTS_DIR}/${__id}"
	fi

	echo "{ \"return\": {\"id\": ${__id}}}"

	NEED_RESTART=1
}

# api_list_one() - Print a single port forwarding entry in JSON
# $1:	ID
# $2:	protocol option, -t or -u
# $3:	host port
# $4:	guest port
api_list_one() {
	[ "${2}" = "-t" ] && __proto="tcp" || __proto="udp"

	printf '{"id": %i, "proto": "%s", "host_addr": "0.0.0.0", "host_port": %i, "guest_addr": "%s", "guest_port": %i}' \
		"${1}" "${__proto}" "${3}" "${A4}" "${4}"
}

# api_list() - Handle list_hostfwd request: list port forwarding entries in JSON
api_list() {
	printf '{ "return": {"entries": ['

	__first=1
	for __entry in $(ls "${PORTS_DIR}"); do
		[ ${__first} -eq 0 ] && printf ", " || __first=0
		IFS=' :'
		api_list_one ${__entry} $(cat ${PORTS_DIR}/${__entry})
		unset IFS
	done

	printf ']}}'
}

# api_delete() - Handle remove_hostfwd request: delete entry, update PORT_ARGS
# $1:	Entry ID -- caller *must* ensure it's a number
api_delete() {
	if [ ! -f "${PORTS_DIR}/${1}" ]; then
		printf '{"error":{"desc":"bad request: remove_hostfwd: bad arguments.id"}}'
		return
	fi

	rm "${PORTS_DIR}/${1}"

	PORT_ARGS=
	for __entry in $(ls ${PORTS_DIR}); do
		PORT_ARGS="${PORT_ARGS} $(cat "${PORTS_DIR}/${__entry}")"
	done

	printf '{"return":{}}'

	NEED_RESTART=1
}

# api_error() - Print generic error in JSON
api_error() {
	printf '{"error":{"desc":"bad request"}}'
}

# api_handler() - Entry point for slirp4netns-like API socket handler
api_handler() {
	trap 'exit 0' INT QUIT TERM
	mkdir "${PORTS_DIR}"

	while true; do
		mkfifo "${FIFO_REQ}" "${FIFO_RESP}"

		cat "${FIFO_RESP}" | nc -l -U "${API_SOCKET}" | \
			tee /dev/null >"${FIFO_REQ}" & READER_PID=${!}

		__req="$(dd count=1 2>/dev/null <${FIFO_REQ})"

		>&2 echo "apifd event"
		>&2 echo "api_handler: got request: ${__req}"

		eval $(echo "${__req}" |
			(jq -r 'to_entries | .[0] |
			 .key + "=" + (.value | @sh)' ||
			 printf 'execute=ERR'))

		if [ "${execute}" != "list_hostfwd" ]; then
			eval $(echo "${__req}" |
				(jq -r '.arguments | to_entries | .[] |
				 .key + "=" + (.value | @sh)' ||
				 printf 'execute=ERR'))
		fi

		NEED_RESTART=0
		case ${execute} in
		"add_hostfwd")
			api_insert "${proto}" "${host_port}" "${guest_port}"
			__restart=1
			;;
		"list_hostfwd")
			api_list
			;;
		"remove_hostfwd")
			case ${id} in
			''|*[!0-9]*)	api_error ;;
			*)		api_delete "${id}"; __restart=1 ;;
			esac
			;;
		*)
			api_error
			;;
		esac >"${FIFO_RESP}"

		kill ${READER_PID}

		rm "${FIFO_REQ}" "${FIFO_RESP}"

		[ ${NEED_RESTART} -eq 1 ] && { stop; start; }
	done

	exit 0
}

# usage() - Print slirpnetns(1) usage and exit indicating failure
# $1:	Invalid option name, if any
usage() {
	[ ${#} -eq 1 ] && printf "%s: invalid option -- '%s'\n" "${0}" "${1}"
	cat << EOF
Usage: ${0} [OPTION]... PID|PATH TAPNAME
User-mode networking for unprivileged network namespaces.

-c, --configure          bring up the interface
-e, --exit-fd=FD         specify the FD for terminating slirp4netns
-r, --ready-fd=FD        specify the FD to write to when the network is configured
-m, --mtu=MTU            specify MTU (default=1500, max=65521)
-6, --enable-ipv6        enable IPv6 (experimental)
-a, --api-socket=PATH    specify API socket path
--cidr=CIDR              specify network address CIDR (default=10.0.2.0/24)
--disable-host-loopback  prohibit connecting to 127.0.0.1:* on the host namespace
--netns-type=TYPE 	 specify network namespace type ([path|pid], default=pid)
--userns-path=PATH	 specify user namespace path
--enable-sandbox         create a new mount namespace (and drop all caps except CAP_NET_BIND_SERVICE if running as the root)
--enable-seccomp         enable seccomp to limit syscalls (experimental)
-h, --help               show this help and exit
-v, --version            show version and exit
EOF
	exit ${USAGE_RET}
}

# version() - Print version
version() {
	echo "slirp4netns-like wrapper for pasta"
	exit 0
}

# gen_addr6() - Generate pseudorandom IPv6 address, changes every second
gen_addr6() {
	printf "fd00"
	n=$(($(xorshift $(date +%S)) % 65536))
	for i in $(seq 2 8); do
		printf ":%04x" ${n}
		n=$(($(xorshift ${n}) % 65536))
	done
}

# Default options
v6=0
get_pid=0
MTU=1500
A4="10.0.2.0"
M4="255.255.255.0"
no_map_gw=0
EFD=0
RFD=0

[ -z "${PASTA}" ] && echo "pasta command not found" && exit ${NOTFOUND_RET}

while getopts ce:r:m:6a:hv-: OPT 2>/dev/null; do
	if [ "${OPT}" = "-" ]; then
		OPT="${OPTARG%%[= ]*}"
		OPTARG="${OPTARG#${OPT}[= ]}"
	fi
	case "${OPT}" in
	c | configure)		add "--config-net"			      ;;
	e | exit-fd)		opt u32 EFD				      ;;
	r | ready-fd)		opt u32 RFD				      ;;
	m | mtu)		opt mtu MTU && sub -m ${MTU}		      ;;
	6 | enable-ipv6)	V6=1					      ;;
	a | api-socket)		opt str API_SOCKET			      ;;
	cidr)			opt net4 A4 M4 && sub -a ${A4} -n ${M4}	      ;;
	disable-host-loopback)	add "--no-map-gw" && no_map_gw=1	      ;;
	netns-type)		: Autodetected				      ;;
	userns-path)		opt_str USERNS_NAME "${OPTARG}"		      ;;
	enable-sandbox) 	: Not supported yet			      ;;
	enable-seccomp)		: Cannot be disabled			      ;;
	h | help)		USAGE_RET=0 && usage			      ;;
	v | version)		version					      ;;
	??*)			usage "${OPT}"				      ;;
	?)			usage "${OPT}"				      ;;
	esac
done

shift $((OPTIND - 1))
[ ${#} -ne 2 ] && usage
ns_spec="${1}"

ifname="${2}"
add "-I ${ifname}"

if [ ${v6} -eq 1 ]; then
	drop "--ipv4-only"
	add "-a $(gen_addr6) -g fd00::2 -D fd00::3"
fi

start
[ -n "${API_SOCKET}" ] && api_handler </dev/null &
trap "stop; rm -rf ${API_DIR}; rm -f ${API_SOCKET}; rm ${PASTA_PID}" EXIT
trap 'exit 0' INT QUIT TERM

>&2 echo "sent tapfd=5 for ${ifname}"
>&2 echo "received tapfd=5"

cat << EOF
Starting slirp
* MTU:             ${MTU}
* Network:         ${A4}
* Netmask:         ${M4}
* Gateway:         10.0.2.2
* DNS:             10.0.2.3
* Recommended IP:  10.0.2.100
EOF
[ -n "${API_SOCKET}" ] && echo "* API socket:      ${API_SOCKET}"

if [ ${no_map_gw} -eq 0 ]; then
	echo "WARNING: 127.0.0.1:* on the host is accessible as 10.0.2.2 (set --disable-host-loopback to prohibit connecting to 127.0.0.1:*)"
fi

if [ ${EFD} -ne 0 ]; then
	dd count=1 of=/dev/null 2>/dev/null <&${EFD}
else
	while read a; do :; done
fi

exit 0
