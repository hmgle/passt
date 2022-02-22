<!---
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (c) 2021-2022 Red Hat GmbH
Author: Stefano Brivio <sbrivio@redhat.com>
-->

# Scope

This directory contains test cases for _passt_ and _pasta_ and a simple
POSIX shell-based framework to define them, and run them as a suite.

These tests can be run as part of a continuous integration workflow, and are
also used to provide short usage demos, with video recording, for _passt_ and
_pasta_ basic use cases.

# Run

## Dependencies

### Packages

The tests require some package dependencies commonly available in Linux
distributions. If some packages are not available, the test groups that need
them will be selectively skipped.

This is a non-exhaustive list of packages that might not commonly be installed
on a system, i.e. common utilities such as a shell are not included here.

Example for Debian, and possibly most Debian-based distributions:

    build-essential git jq strace iperf3 qemu-system-x86 tmux sipcalc bc
    clang-tidy cppcheck isc-dhcp-common udhcpc psmisc linux-cpupower
    netcat-openbsd fakeroot lz4 lm-sensors qemu-system-arm qemu-system-ppc
    qemu-system-misc qemu-system-x86`

### Other tools

Test measuring request-response and connect-request-response latencies use
`neper`, which is not commonly packaged by distributions and needs to be built
and installed manually:

    git clone https://github.com/google/neper
    cd neper; make
    cp tcp_crr tcp_rr udp_rr /usr/local/bin

Virtual machine images are built during test executions using
[mbuto](https://mbuto.lameexcu.se/), the shell script is sourced via _git_
as needed, so there's no need to actually install it.

### Special requirements for continuous integration and demo modes

Running the test suite as continuous integration or demo modes will record the
terminal with the steps being executed, using asciinema(1), and create binary
packages.

The following additional packages are commonly needed:

    alien linux-perf tshark

## Regular test

Just issue:

    ./run

from the `test` directory. Elevated privileges are not needed.

## Continuous integration

Issuing:

    ./ci

will run the whole test suite while recording the execution, and it will also
build JavaScript fragments used on http://passt.top/ for performance data tables
and links to specific offsets in the captures.

## Demo mode

Issuing:

    ./demo

will run the demo cases under `demo`, with terminal captures as well.

# Framework

The implementation of the testing framework is under `lib`, and it provides
facilities for terminal and _tmux_ session management, interpretation of test
directives, video recording, and suchlike. Test cases are organised in the
remaining directories.

Test cases can be implemented as POSIX shell scripts, or as a set of directives,
which are not formally documented here, but should be clear enough from the
existing cases. The entry point for interpretation of test directives is
implemented in `lib/test`.
