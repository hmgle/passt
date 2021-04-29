# passt: Plug A Simple Socket Transport

_passt_ implements a translation layer between a Layer-2 network interface (tap)
and native Layer-4 sockets (TCP, UDP, ICMP/ICMPv6 echo) on a host. It doesn't
require any capabilities or privileges, and it can be used as a simple
replacement for Slirp.

<img src="/builds/passt_overview.png" usemap="#image-map" class="bright" style="z-index: 20; position: relative;">
<map name="image-map" id="map_overview">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/tcp.7.html" coords="229,275,246,320,306,294,287,249" shape="poly">
    <area class="map_area" target="_blank" href="https://lwn.net/Articles/420799/" coords="230,201,243,246,297,232,289,186" shape="poly">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/udp.7.html" coords="234,129,236,175,297,169,293,126" shape="poly">
    <area class="map_area" target="_blank" href="https://en.wiktionary.org/wiki/passen#German" coords="387,516,841,440,847,476,393,553" shape="poly">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c" coords="398,123,520,157" shape="rect">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ping.c" coords="397,164,517,197" shape="rect">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp.c" coords="398,203,516,237" shape="rect">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/unix.7.html" coords="569,306,674,359" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/udp.c" coords="719,152,740,176,792,134,768,108" shape="poly">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/icmp.c" coords="727,206,827,120,854,150,754,238" shape="poly">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/tcp.c" coords="730,273,774,326,947,176,902,119" shape="poly">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/igmp.c" coords="865,273,912,295" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/arp.c" coords="854,300,897,320" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/ndp.c" coords="869,325,909,344" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/mld.c" coords="924,267,964,289" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/dhcpv6.c" coords="918,297,986,317" shape="rect">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/dhcp.c" coords="931,328,981,352" shape="rect">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/udp.7.html" coords="1073,115,1059,154,1120,176,1133,137" shape="poly">
    <area class="map_area" target="_blank" href="https://lwn.net/Articles/420799/" coords="966,113,942,152,1000,175,1017,136" shape="poly">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/tcp.7.html" coords="1059,175,1039,213,1098,237,1116,197" shape="poly">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c" coords="1203,154,1326,189" shape="rect">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ping.c" coords="1202,195,1327,228" shape="rect">
    <area class="map_area" target="_blank" href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp.c" coords="1204,236,1327,269" shape="rect">
    <area class="map_area" target="_blank" href="https://en.wikipedia.org/wiki/OSI_model#Layer_architecture" coords="1159,52,1325,147" shape="rect">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man4/veth.4.html" coords="1119,351,1157,339,1198,340,1236,345,1258,359,1229,377,1176,377,1139,375,1114,365" shape="poly">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man4/veth.4.html" coords="1044,471,1090,461,1126,462,1150,464,1176,479,1160,491,1121,500,1081,501,1044,491,1037,483" shape="poly">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/network_namespaces.7.html" coords="240,379,524,452" shape="rect">
    <area class="map_area" target="_blank" href="https://man7.org/linux/man-pages/man7/netlink.7.html" coords="1119,278,1117,293,1165,304,1169,288" shape="poly">
    <area class="map_area" target="_blank" href="https://passt.top/passt/tree/passt.c#n195" coords="989,294,1040,264,1089,280,986,344" shape="poly">
</map>
<canvas id="map_highlight" style="border: 0px; z-index: 10; position: fixed; pointer-events: none"></canvas>
<script>
function canvas_position(el) {
	var rect = el.getBoundingClientRect();
	var canvas = document.getElementById('map_highlight');

	canvas.width = rect.right - rect.left;
	canvas.height = rect.bottom - rect.top;
	canvas.style.left = rect.left + 'px';
	canvas.style.top = rect.top + 'px';
}

function map_hover() {
	var coords = this.coords.split(',');
	var canvas = document.getElementById('map_highlight');
	var ctx = canvas.getContext('2d');

	canvas_position(this);

	ctx.fillStyle = 'rgba(255, 255, 255, .3)';
	ctx.lineWidth = 1.5;
	ctx.strokeStyle = 'rgba(255, 255, 100, 1)';

	ctx.beginPath();
	ctx.setLineDash([15, 15]);
	if (this.shape == "poly") {
		ctx.moveTo(coords[0], coords[1]);
		for (item = 2; item < coords.length - 1; item += 2) {
			ctx.lineTo(coords[item], coords[item + 1])
		}
	} else if (this.shape == "rect") {
		ctx.rect(coords[0], coords[1],
			 coords[2] - coords[0], coords[3] - coords[1]);
	}

	ctx.closePath();
	ctx.stroke();
	ctx.fill();
}

function map_out() {
	var canvas = document.getElementById('map_highlight');
	var ctx = canvas.getContext('2d');

	ctx.clearRect(0, 0, canvas.width, canvas.height);
}

var map_areas = document.getElementsByClassName("map_area");

for (var i = 0; i < map_areas.length; i++) {
	map_areas[i].onmouseover = map_hover;
	map_areas[i].onmouseout = map_out;
}
</script>

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
however, as this layer runs without the `CAP_NET_RAW` capability: we can't
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

* [ARP proxy](https://passt.top/passt/tree/arp.c), that resolves the address of
  the host (which is used as gateway) to the original MAC address of the host
* [DHCP server](https://passt.top/passt/tree/dhcp.c), a simple implementation
  handing out one single IPv4 address to the guest, namely, the same address as
  the first one configured for the upstream host interface, and passing the
  nameservers configured on the host
* [NDP proxy](https://passt.top/passt/tree/ndp.c), which can also assign prefix
  and nameserver using SLAAC
* [DHCPv6 server](https://passt.top/passt/tree/dhcpv6.c): a simple
  implementation handing out one single IPv6 address to the guest, namely, the
  the same address as the first one configured for the upstream host interface,
  and passing the first nameserver configured on the host

## Addresses

For IPv4, the guest is assigned, via DHCP, the same address as the upstream
interface of the host, and the same default gateway as the default gateway of
the host. Addresses are translated in case the guest is seen using a different
address from the assigned one.

For IPv6, the guest is assigned, via SLAAC, the same prefix as the upstream
interface of the host, the same default route as the default route of the
host, and, if a DHCPv6 client is running on the guest, also the same address as
the upstream address of the host. This means that, with a DHCPv6 client on the
guest, addresses don't need to be translated. Should the client use a different
address, the destination address is translated for packets going to the guest.

For UDP and TCP, for both IPv4 and IPv6, packets addressed to a loopback address
are forwarded to the guest with their source address changed to the address of
the gateway or first hop of the default route. This mapping is reversed as the
guest replies to those packets (on the same TCP connection, or using destination
port and address that were used as source for UDP).

## Protocols

_passt_ supports TCP, UDP and ICMP/ICMPv6 echo (requests and replies). More
details about the TCP implementation are available
[here](https://passt.top/passt/tree/tcp.c), and for the UDP
implementation [here](https://passt.top/passt/tree/udp.c).

An IGMP proxy is currently work in progress.

## Ports

To avoid the need for explicit port mapping configuration, _passt_ binds to all
unbound non-ephemeral (0-49152) TCP and UDP ports. Binding to low ports (0-1023)
will fail without additional capabilities, and ports already bound (service
proxies, etc.) will also not be used.

UDP ephemeral ports are bound dynamically, as the guest uses them.

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

* alternatively, you can use libvirt, with [this patch](https://passt.top/passt/tree/libvirt/0001-conf-Introduce-support-for-UNIX-domain-socket-as-qem.patch),
  to start qemu (with the patch mentioned above), with this kind of network
  interface configuration:

        <interface type='client'>
          <mac address='52:54:00:02:6b:60'/>
          <source path='/tmp/passt.socket'/>
          <model type='virtio'/>
          <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
        </interface>

* and that's it, you should now have TCP connections, UDP, and ICMP/ICMPv6
  echo working from/to the guest for IPv4 and IPv6

* to connect to a service on the VM, just connect to the same port directly
  with the address of the network namespace. For example, to ssh to the guest,
  from the main namespace on the host:

        ssh 192.0.2.2

## Contribute

Send patches and issue reports to [sbrivio@redhat.com](mailto:sbrivio@redhat.com).
