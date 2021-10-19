# SPDX-License-Identifier: AGPL-3.0-or-later
#
# PASST - Plug A Simple Socket Transport
#  for qemu/UNIX domain socket mode
#
# PASTA - Pack A Subtle Tap Abstraction
#  for network namespace/tap device mode
#
# Copyright (c) 2021 Red Hat GmbH
# Author: Stefano Brivio <sbrivio@redhat.com>

CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -DRLIMIT_STACK_VAL=$(shell ulimit -s)
CFLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
CFLAGS += -DNETNS_RUN_DIR=\"/run/netns\"
CFLAGS += -DPASST_AUDIT_ARCH=AUDIT_ARCH_$(shell uname -m | tr [a-z] [A-Z])

# On gcc 11.2, with -O2 and -flto, tcp_hash() and siphash_20b(), if inlined,
# seem to be hitting something similar to:
#	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=78993
# from the pointer arithmetic used from the tcp_tap_handler() path to get the
# remote connection address.
ifeq ($(shell $(CC) -dumpversion),11)
ifneq (,$(filter -flto%,$(CFLAGS)))
ifneq (,$(filter -O2,$(CFLAGS)))
	CFLAGS += -DTCP_HASH_NOINLINE
	CFLAGS += -DSIPHASH_20B_NOINLINE
endif
endif
endif

prefix ?= /usr/local

all: passt pasta passt4netns qrap

avx2: CFLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
avx2: clean all

static: CFLAGS += -static -DGLIBC_NO_STATIC_NSS
static: clean all

seccomp.h: *.c $(filter-out seccomp.h,$(wildcard *.h))
	@ ./seccomp.sh

passt: $(filter-out qrap.c,$(wildcard *.c)) \
	$(filter-out qrap.h,$(wildcard *.h)) seccomp.h
	$(CC) $(CFLAGS) $(filter-out qrap.c,$(wildcard *.c)) -o passt

pasta: passt
	ln -s passt pasta
	ln -s passt.1 pasta.1

passt4netns: passt
	ln -s passt passt4netns

qrap: qrap.c passt.h
	$(CC) $(CFLAGS) -DARCH=\"$(shell uname -m)\" \
		qrap.c -o qrap

.PHONY: clean
clean:
	-${RM} passt *.o seccomp.h qrap pasta pasta.1 passt4netns \
		passt.tar passt.tar.gz *.deb *.rpm

install: passt pasta qrap
	mkdir -p $(DESTDIR)$(prefix)/bin $(DESTDIR)$(prefix)/share/man/man1
	cp -d passt pasta qrap $(DESTDIR)$(prefix)/bin
	cp -d passt.1 pasta.1 qrap.1 $(DESTDIR)$(prefix)/share/man/man1

uninstall:
	-${RM} $(DESTDIR)$(prefix)/bin/passt
	-${RM} $(DESTDIR)$(prefix)/bin/pasta
	-${RM} $(DESTDIR)$(prefix)/bin/qrap
	-${RM} $(DESTDIR)$(prefix)/share/man/man1/passt.1
	-${RM} $(DESTDIR)$(prefix)/share/man/man1/pasta.1
	-${RM} $(DESTDIR)$(prefix)/share/man/man1/qrap.1

pkgs:
	tar cf passt.tar -P --xform 's//\/usr\/bin\//' passt pasta qrap
	tar rf passt.tar -P --xform 's//\/usr\/share\/man\/man1\//' \
		passt.1 pasta.1 qrap.1
	gzip passt.tar
	EMAIL="sbrivio@redhat.com" fakeroot alien --to-deb \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=$(shell git rev-parse --short HEAD) \
		passt.tar.gz
	fakeroot alien --to-rpm --target=$(shell uname -m) \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=g$(shell git rev-parse --short HEAD) passt.tar.gz

# Checkers currently disabled for clang-tidy:
# - llvmlibc-restrict-system-libc-headers
#	TODO: this is Linux-only for the moment, nice to fix eventually
#
# - bugprone-macro-parentheses
# - google-readability-braces-around-statements
# - hicpp-braces-around-statements
# - readability-braces-around-statements
#	Debatable whether that improves readability, right now it would look
#	like a mess
#
# - readability-magic-numbers
# - cppcoreguidelines-avoid-magic-numbers
#	TODO: in most cases they are justified, but probably not everywhere
#
# - clang-analyzer-valist.Uninitialized
#	TODO: enable once https://bugs.llvm.org/show_bug.cgi?id=41311 is fixed
#
# - clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling
#	Probably not doable to impement this without plain memcpy(), memset()
#
# - cppcoreguidelines-init-variables
#	Dubious value, would kill readability
#
# - hicpp-signed-bitwise
#	Those are needed for syscalls, epoll_wait flags, etc.
#
# - bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp
#	This flags _GNU_SOURCE, currently needed
#
# - llvm-include-order
#	TODO: not really important, but nice to fix eventually
#
# - readability-isolate-declaration
#	Dubious value, would kill readability
#
# - android-cloexec-open
# - android-cloexec-pipe
# - android-cloexec-pipe2
# - android-cloexec-epoll-create1
#	TODO: check, fix except for the few cases where we need to share fds
#
# - bugprone-narrowing-conversions
# - cppcoreguidelines-narrowing-conversions
#	TODO: nice to fix eventually
#
# - cppcoreguidelines-avoid-non-const-global-variables
#	TODO: check, fix, and more in general constify wherever possible
#
# - bugprone-suspicious-string-compare
#	Return value of memcmp(), not really suspicious
clang-tidy: $(wildcard *.c)
	clang-tidy -checks=*,-modernize-*,\
	-clang-analyzer-valist.Uninitialized,\
	-cppcoreguidelines-init-variables,\
	-bugprone-macro-parentheses,\
	-google-readability-braces-around-statements,\
	-hicpp-braces-around-statements,\
	-readability-braces-around-statements,\
	-readability-magic-numbers,\
	-llvmlibc-restrict-system-libc-headers,\
	-hicpp-signed-bitwise,\
	-bugprone-reserved-identifier,-cert-dcl37-c,-cert-dcl51-cpp,\
	-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,\
	-llvm-include-order,\
	-cppcoreguidelines-avoid-magic-numbers,\
	-readability-isolate-declaration,\
	-android-cloexec-open,-android-cloexec-pipe,-android-cloexec-pipe2,\
	-android-cloexec-epoll-create1,\
	-bugprone-narrowing-conversions,\
	-cppcoreguidelines-narrowing-conversions,\
	-cppcoreguidelines-avoid-non-const-global-variables,\
	-bugprone-suspicious-string-compare \
	--warnings-as-errors=* $(wildcard *.c) -- $(CFLAGS)
