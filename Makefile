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

RLIMIT_STACK_VAL := $(shell /bin/sh -c 'ulimit -s')
ifeq ($(RLIMIT_STACK_VAL),unlimited)
RLIMIT_STACK_VAL := 1024
endif

AUDIT_ARCH := $(shell uname -m | tr [a-z] [A-Z])
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

CFLAGS += -Wall -Wextra -pedantic -std=c99 -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CFLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
CFLAGS += -DNETNS_RUN_DIR=\"/run/netns\"
CFLAGS += -DPASST_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
CFLAGS += -DRLIMIT_STACK_VAL=$(RLIMIT_STACK_VAL)
CFLAGS += -DARCH=\"$(shell uname -m)\"

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

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_snd_wnd = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	CFLAGS += -DHAS_SND_WND
endif

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_bytes_acked = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	CFLAGS += -DHAS_BYTES_ACKED
endif

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_min_rtt = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	CFLAGS += -DHAS_MIN_RTT
endif

C := \#include <sys/random.h>\nint main(){int a=getrandom(0, 0, 0);}
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	CFLAGS += -DHAS_GETRANDOM
endif

prefix ?= /usr/local

all: passt pasta qrap

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

qrap: qrap.c passt.h
	$(CC) $(CFLAGS) \
		qrap.c -o qrap

.PHONY: clean
clean:
	-${RM} passt *.o seccomp.h qrap pasta pasta.1 \
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
#
# - altera-unroll-loops
# - altera-id-dependent-backward-branch
#	TODO: check paths where it might make sense to improve performance
#
# - bugprone-easily-swappable-parameters
#	Not much can be done about them other than being careful
#
# - readability-function-cognitive-complexity
#	TODO: split reported functions
#
# - altera-struct-pack-align
#	"Poor" alignment needed for structs reflecting message formats/headers
#
# - concurrency-mt-unsafe
#	TODO: check again if multithreading is implemented

clang-tidy: $(wildcard *.c) $(wildcard *.h)
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
	-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling,\
	-llvm-include-order,\
	-cppcoreguidelines-avoid-magic-numbers,\
	-readability-isolate-declaration,\
	-android-cloexec-open,-android-cloexec-pipe,-android-cloexec-pipe2,\
	-android-cloexec-epoll-create1,\
	-bugprone-narrowing-conversions,\
	-cppcoreguidelines-narrowing-conversions,\
	-cppcoreguidelines-avoid-non-const-global-variables,\
	-bugprone-suspicious-string-compare,\
	-altera-unroll-loops,-altera-id-dependent-backward-branch,\
	-bugprone-easily-swappable-parameters,\
	-readability-function-cognitive-complexity,\
	-altera-struct-pack-align,\
	-concurrency-mt-unsafe \
	--warnings-as-errors=* $(wildcard *.c) -- $(CFLAGS)

ifeq ($(shell $(CC) -v 2>&1 | grep -c "gcc version"),1)
TARGET := $(shell ${CC} -v 2>&1 | sed -n 's/Target: \(.*\)/\1/p')
VER := $(shell $(CC) -dumpversion)
EXTRA_INCLUDES := /usr/lib/gcc/$(TARGET)/$(VER)/include
EXTRA_INCLUDES_OPT := -I$(EXTRA_INCLUDES)
else
EXTRA_INCLUDES_OPT :=
endif
cppcheck: $(wildcard *.c) $(wildcard *.h)
	cppcheck --std=c99 --error-exitcode=1 --enable=all --force	\
	--inconclusive --library=posix					\
	-I/usr/include $(EXTRA_INCLUDES_OPT)				\
									\
	--suppress=syntaxError:/usr/include/stdlib.h			\
	--suppress=missingIncludeSystem					\
	--suppress="*:$(EXTRA_INCLUDES)/avx512fintrin.h"		\
	--suppress="*:$(EXTRA_INCLUDES)/xmmintrin.h"			\
	--suppress="*:$(EXTRA_INCLUDES)/emmintrin.h"			\
	--suppress="*:$(EXTRA_INCLUDES)/avxintrin.h"			\
	--suppress="*:$(EXTRA_INCLUDES)/bmiintrin.h"			\
									\
	--suppress=objectIndex:tcp.c --suppress=objectIndex:udp.c	\
	--suppress=va_list_usedBeforeStarted:util.c			\
	--suppress=unusedFunction					\
	--suppress=knownConditionTrueFalse:conf.c			\
	--suppress=strtokCalled:conf.c --suppress=strtokCalled:qrap.c	\
	--suppress=getpwnamCalled:passt.c				\
	--suppress=localtimeCalled:pcap.c				\
	--suppress=unusedStructMember:pcap.c				\
	--suppress=funcArgNamesDifferent:util.h				\
									\
	--suppress=unmatchedSuppression:conf.c				\
	--suppress=unmatchedSuppression:passt.c				\
	--suppress=unmatchedSuppression:pcap.c				\
	--suppress=unmatchedSuppression:qrap.c				\
	--suppress=unmatchedSuppression:tcp.c				\
	--suppress=unmatchedSuppression:udp.c				\
	--suppress=unmatchedSuppression:util.c				\
	--suppress=unmatchedSuppression:util.h				\
	$(filter -D%,$(CFLAGS))						\
	.
