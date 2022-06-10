This document shows how to set up a Kata Containers environment using passt to
implement user-mode networking: contrary to other networking models currently
implemented, this kind of setup requires no elevated privileges or capabilities
as far as networking is concerned.

This proof-of-concept uses CRI-O as implementation container runtime, which is
controlled directly without resorting to a full Kubernetes environment.

# Pre-requisites

* Go and rust toolchains, typically provided by distribution packages
* the usual tools, such as git, make, etc.
* a 4.x qemu version, or more recent, with a working virtiofsd executable
  (provided at least by Debian, Ubuntu, Fedora packages)

# Fetch and prepare components

## CRI-O

CRI-O is the container runtime. It implements the Kubernetes CRI (Container
Runtime Interface) on one side -- and we'll handle that part manually with
`crictl` here, and on the other side it supports OCI (Open Container Initiative)
runtimes -- Kata Containers is one of them.

### Fetch

    git clone https://github.com/cri-o/cri-o.git

### Build

    cd cri-o
    make

### Install

As root:

    make install

### Configure

Configuration is now at `/etc/crio/crio.conf`. This would also be the case for
distribution packages. Some specific configuration items for Kata Containers
are:

    # Cgroup management implementation used for the runtime.
    cgroup_manager = "cgroupfs"

    # manage_ns_lifecycle determines whether we pin and remove namespaces
    # and manage their lifecycle
    manage_ns_lifecycle = true

and the following section, that can be added at the end, defines a special type
of runtime, the `vm` type. This is needed to run the Kata Containers runtime
instead of the default `crun` choice:

    [crio.runtime.runtimes.kata]
    runtime_path = "/usr/local/bin/containerd-shim-kata-v2"
    runtime_type = "vm"
    runtime_root = "/run/vc"

Note that we don't have a containerd-shim-kata-v2 binary yet, we'll deal with
that in the next steps.

## CNI plugins

CNI plugins are actually binaries, run by CRI-O, used to configure networking on
the host as well as on the pod side. A few network topologies are offered, with
very limited capabilities.

### Fetch

    git clone https://github.com/containernetworking/plugins

### Build

    cd plugins
    ./build_linux.sh

### Install

As root:

    mkdir -p /opt/cni/bin
    cp bin/* /opt/cni/bin/


### Configure

The path where CNI configurations are located is configurable in
`/etc/crio/crio.conf`, see the `network_dir` parameter there. Assuming the
default value, we need to provide at least one configuration under
`/etc/cni/net.d/`. For example:

    # cat /etc/cni/net.d/50-kata-sandbox.conf 
    {
        "cniVersion": "0.3.0",
        "name": "crio-bridge",
        "type": "bridge",
        "bridge": "cni0",
        "isGateway": true,
        "ipMasq": true,
        "ipam": {
            "type": "host-local",
            "subnet": "10.88.0.0/16",
            "routes": [
                { "dst": "0.0.0.0/0" }
            ]
        }
    }

## crictl

`crictl` is needed to control CRI-O in lieu of Kubernetes.

### Fetch

    git clone https://github.com/kubernetes-sigs/cri-tools.git

### Build

    cd cri-tools
    make

### Install

As root:

    make install

## mbuto

We'll use `mbuto` to build a minimal virtual machine image for usage with the
Kata Containers runtime.

### Fetch

    git clone https://mbuto.lameexcu.se/mbuto

## Kata Containers

### Fetch

    git clone https://github.com/kata-containers/kata-containers

### Patch

The current upstream version doesn't support the _passt_ networking model yet,
use the patch from this directory to add it:

    patch -p1 < 0001-virtcontainers-agent-Add-passt-networking-model-and-.patch

### Build

    make -C src/runtime
    make -C src/agent LIBC=gnu

### Install

As root:

    make -C src/runtime install
    cp src/agent/target/x86_64-unknown-linux-gnu/release/kata-agent /usr/libexec/
    chmod 755 /usr/libexec/kata-agent

### Build the Virtual Machine image

    cd mbuto
    ./mbuto -f /tmp/kata.img

See `mbuto -h` for additional parameters, such as choice of kernel version,
kernel modules, program add-ons, etc. `mbuto` will print some configuration
parameters to be used in the configuration of the Kata Containers runtime below.
For example:

    $ ./mbuto -c lz4 -f /tmp/kata.img
    Not running as root, won't keep cpio mounted
    Size: bin   12M lib   59M kmod  1.4M total   70M compressed   33M
    Kata Containers [hypervisor.qemu] configuration:
    
    	kernel = "/boot/vmlinuz-5.10.0-6-amd64"
    	initrd = "/tmp/kata.img"

### Configure

The configuration file at this point is located at
`/usr/share/defaults/kata-containers/configuration-qemu.toml`. Some parameters of general interest are:

    [hypervisor.qemu]
    kernel = "/boot/vmlinuz-5.10.0-6-amd64"
    initrd = "/tmp/kata.img"

where we can use the values indicated earlier by `mbuto`. Currently, the default
path for the `virtiofsd` daemon doesn't work for all distributions, ensure that
it matches. For example, on Debian:

    virtio_fs_daemon = "/usr/lib/qemu/virtiofsd"

we'll then need to enable the `passt` networking model for the runtime. In the
`[runtime]` section:

    	internetworking_model=passt

# Run an example container

## Fetch

We'll now need an image of a container to run as example. With `podman`
installed via distribution package, we can import one:

    podman pull docker.io/i386/busybox

## Configure

Now we can define configuration files for pod and container we want to create
and start:

    $ cat pod-config.json
    {
        "metadata": {
            "name": "kata-sandbox",
            "namespace": "default",
            "attempt": 1,
            "uid": "hdishd83djaidwnduwk28bcsb"
        },
        "logDirectory": "/tmp",
        "linux": {
        }
    }

    $ cat container-busybox.json
    {
      "metadata": {
          "name": "kata-busybox"
      },
      "image": {
          "image": "docker.io/i386/busybox"
      },
      "command": [
          "sleep", "6000"
      ],
      "log_path":"kata-busybox.log",
      "linux": {
      }
    }

## Run the container workload

Assuming we have `pod-config.json` and `container-busybox.json` defined above,
we can now:

### start CRI-O

    crio -l debug

### create the pod and run a container inside it

    c=$(crictl start $(crictl create $(crictl runp --runtime=kata pod-config.json) container-dpdk.json pod-config.json))

### verify that addresses are properly configured

    crictl exec $c ip addr show

## Enable support for ICMP/ICMPv6 Echo Request

_passt_ can replicate ICMP Echo Requests sent by the workload, and propagate the
replies back. However, as it's not running as root, we need to enable so-called
_ping_ sockets for unprivileged users. From the namespace created by CRI-O for
this container:

    sysctl -w net.ipv4.ping_group_range=net.ipv4.ping_group_range = 0 2147483647

# Troubleshooting

## Redirect qemu's console output to file

Agent errors and kernel messages should be accessible via named UNIX domain
socket at `/run/vc/vm/*/console.sock`, provided `agent.debug_console` is enabled
in `kernel_params` of `configuration.toml` but this won't work if the agent
doesn't start. In order to get those, we can wrap `qemu` and get, additionally,
all the output piped to a file:

    $ cat /usr/local/bin/qemu.sh
    #!/bin/sh
    
    /usr/bin/qemu-system-x86_64 "$@" -serial file:/tmp/qemu.log 2>/tmp/qemu_err.log

now, use this as path for `qemu` in `configuration.toml`:

    [hypervisor.qemu]
    path = "/usr/local/bin/qemu.sh"

and don't forget to add `console=ttyS0` to the kernel parameters, so that kernel
messages will also be included:

    kernel_params = "... console=ttyS0"

## Debug console

See the `kata-console` script in the
[kata-vfio-tools repository](https://github.com/dgibson/kata-vfio-tools) for a
convenient helper to access the debug console provided by the agent.
