# passt: Plug A Simple Socket Transport

_passt_ implements a translation layer between a Layer-2 network interface (tap)
and native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
require any capabilities or privileges, and it can be used as a simple
replacement for Slirp.

- [General idea](#general-idea)
- [Non-functional Targets](#non-functional-targets)
- [Interfaces and Environment](#interfaces-and-environment)
- [Services](#services)
- [Addresses](#addresses)
- [Protocols](#protocols)
- [Ports](#ports)
- [Try it](#try-it)
- [Contribute](#contribute)

## General idea

When container workloads are moved to virtual machines, the network traffic is
typically forwarded by interfaces operating at data link level. Some components
in the containers ecosystem (such as _service meshes_), however, expect
applications to run locally, with visible sockets and processes, for the
purposes of socket redirection, monitoring, port mapping.

To solve this issue, user mode networking as provided e.g. by _Slirp_,
_libslirp_, _slirp4netns_ can be used. However, these existing solutions
implement a full TCP/IP stack, replaying traffic on sockets that are local to
the pod of the service mesh. This creates the illusion of application processes
running on the same host, eventually separated by user namespaces.

While being almost transparent to the service mesh infrastructure, that kind of
solution comes with a number of downsides:

* three different TCP/IP stacks (guest, adaptation and host) need to be
  traversed for every service request. There are no chances to implement
  zero-copy mechanisms, and the amount of context switches increases
  dramatically
* addressing needs to be coordinated to create the pretense of consistent
  addresses and routes between guest and host environments. This typically needs
  a NAT with masquerading, or some form of packet bridging
* the traffic seen by the service mesh and observable externally is a distant
  replica of the packets forwarded to and from the guest environment:
  * TCP congestion windows and network buffering mechanisms in general operate
    differently from what would be naturally expected by the application
  * protocols carrying addressing information might pose additional challenges,
    as the applications don't see the same set of addresses and routes as they
    would if deployed with regular containers

_passt_ implements a thinner layer between guest and host, that only implements
what's strictly needed to pretend processes are running locally. A further, full
TCP/IP stack is not necessarily needed. Some sort of TCP adaptation is needed,
however, as this layer runs without the `CAP\_NET\_RAW` capability: we can't
create raw IP sockets on the pod, and therefore need to map packets at Layer-2
to Layer-4 sockets offered by the host kernel.

The problem and this approach are illustrated in more detail, with diagrams,
[here](https://gitlab.com/abologna/kubevirt-and-kvm/-/blob/master/Networking.md).

## Non-functional Targets

Security and maintainability goals:

* no dynamic memory allocation
* ~2 000 LoC target
* no external dependencies

## Interfaces and Environment

_passt_ exchanges packets with _qemu_ via UNIX domain socket, using the `socket`
back-end in qemu. Currently, qemu can only connect to a listening process via
TCP. Two temporary solutions are available:

* a [patch](https://passt.top/passt/tree/qemu) for qemu
* a wrapper, [qrap](https://passt.top/passt/tree/qrap.c), that connects to a
  UNIX domain socket and starts qemu, which can now use the file descriptor
  that's already opened

This approach, compared to using a _tap_ device, doesn't require any security
capabilities, as we don't need to create any interface.

## Services

_passt_ provides some minimalistic implementations of networking services that
can't practically run on the host:

* [ARP proxy](https://passt.top/passt/tree/arp.c), that resolve the address of
  the host (which is used as gateway) to the original MAC address of the host
* [DHCP server](https://passt.top/passt/tree/dhcp.c), a simple implementation
  handing out one single IPv4 address to the guest, namely, the same address as
  the first one configured for the upstream host interface, and passing the
  nameservers configured on the host
* [NDP proxy](https://passt.top/passt/tree/ndp.c), which can also assign prefix
  and nameserver using SLAAC
* _to be done_: DHCPv6 server: right now, the guest gets the same _prefix_ as
  the host, but not the same address, because the suffix is generated from the
  MAC address of the virtual machine, so we currently have to translate packet
  addresses back and forth. With a DHCPv6 server, we could simply assign the
  host address to the guest

## Addresses

For IPv4, the guest is assigned, via DHCP, the same address as the upstream
interface of the host, and the same default gateway as the default gateway of
the host. Addresses are never translated.

For IPv6, the guest is assigned, via SLAAC, the same prefix as the upstream
interface of the host, and the same default route as the default route of the
host. This means that the guest will typically have a different address, and
the destination address is translated for packets going to the guest. This will
be avoided in the future once a minimalistic DHCPv6 server is implemented in
_passt_.

## Protocols

_passt_ supports TCP, UDP and ICMP/ICMPv6 echo (requests and replies). More
details about the TCP implementation are available
[here](https://passt.top/passt/tree/tcp.c), and for the UDP
implementation [here](https://passt.top/passt/tree/udp.c).

An IGMP proxy is currently work in progress.

## Ports

To avoid the need for explicit port mapping configuration, _passt_ binds to all
unbound non-ephemeral (0-49152) TCP ports and all unbound (0-65536) UDP ports.
Binding to low ports (0-1023) will fail without additional capabilities, and
ports already bound (service proxies, etc.) will also not be used.

Service proxies and other services running in the container need to be started
before _passt_ starts.

## Try it

* build from source:

        git clone https://passt.top/passt
        cd passt
        make

* a static build for x86_64 as of the latest commit is also available for
  convenience [here](https://passt.top/builds/static/). These binaries are
  simply built with:

        CFLAGS="-static" make

* run the demo script, that creates a network namespace called `passt`, sets up
  sets up a _veth_ pair and and addresses, together with NAT for IPv4 and NDP
  proxying for IPv6, then starts _passt_ in the network namespace:

        doc/demo.sh

* from the same network namespace, start qemu. At the moment, qemu doesn't
  support UNIX domain sockets for the `socket` back-end. Two alternatives:

  * use the _qrap_ wrapper, which maps a tap socket descriptor to _passt_'s
    UNIX domain socket, for example:

            ip netns exec passt ./qrap 5 qemu-system-x86_64 ... -net socket,fd=5 -net nic,model=virtio ...

  * or patch qemu with [this patch](https://passt.top/passt/tree/qemu/0001-net-Allow-also-UNIX-domain-sockets-to-be-used-as-net.patch)
    and start it like this:

            qemu-system-x86_64 ... -net socket,connect=/tmp/passt.socket -net nic,model=virtio

* and that's it, you should now have TCP connections, UDP, and ICMP/ICMPv6
  echo working from/to the guest for IPv4 and IPv6

* to connect to a service on the VM, just connect to the same port directly
  with the address of the network namespace. For example, to ssh to the guest,
  from the main namespace on the host:

        ssh 192.0.2.2

## Contribute

Send patches and issue reports to [sbrivio@redhat.com](mailto:sbrivio@redhat.com).
