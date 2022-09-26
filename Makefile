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

TARGET := $(shell $(CC) -dumpmachine)
# Get 'uname -m'-like architecture description for target
TARGET_ARCH := $(shell echo $(TARGET) | cut -f1 -d- | tr [A-Z] [a-z])
TARGET_ARCH := $(shell echo $(TARGET_ARCH) | sed 's/powerpc/ppc/')

AUDIT_ARCH := $(shell echo $(TARGET_ARCH) | tr [a-z] [A-Z] | sed 's/^ARM.*/ARM/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/I[456]86/I386/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPC64/PPC/')
AUDIT_ARCH := $(shell echo $(AUDIT_ARCH) | sed 's/PPCLE/PPC64LE/')

FLAGS := -Wall -Wextra -pedantic -std=c99 -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
FLAGS += -D_FORTIFY_SOURCE=2 -O2 -pie -fPIE
FLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
FLAGS += -DNETNS_RUN_DIR=\"/run/netns\"
FLAGS += -DPASST_AUDIT_ARCH=AUDIT_ARCH_$(AUDIT_ARCH)
FLAGS += -DRLIMIT_STACK_VAL=$(RLIMIT_STACK_VAL)
FLAGS += -DARCH=\"$(TARGET_ARCH)\"

PASST_SRCS = arch.c arp.c checksum.c conf.c dhcp.c dhcpv6.c icmp.c igmp.c \
	isolation.c lineread.c mld.c ndp.c netlink.c packet.c passt.c pasta.c \
	pcap.c siphash.c tap.c tcp.c tcp_splice.c udp.c util.c
QRAP_SRCS = qrap.c
SRCS = $(PASST_SRCS) $(QRAP_SRCS)

MANPAGES = passt.1 pasta.1 qrap.1

PASST_HEADERS = arch.h arp.h checksum.h conf.h dhcp.h dhcpv6.h icmp.h \
	isolation.h lineread.h ndp.h netlink.h packet.h passt.h pasta.h \
	pcap.h port_fwd.h siphash.h tap.h tcp.h tcp_splice.h udp.h util.h
HEADERS = $(PASST_HEADERS) seccomp.h

# On gcc 11.2, with -O2 and -flto, tcp_hash() and siphash_20b(), if inlined,
# seem to be hitting something similar to:
#	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=78993
# from the pointer arithmetic used from the tcp_tap_handler() path to get the
# remote connection address.
ifeq ($(shell $(CC) -dumpversion),11)
ifneq (,$(filter -flto%,$(FLAGS) $(CFLAGS)))
ifneq (,$(filter -O2,$(FLAGS) $(CFLAGS)))
	FLAGS += -DTCP_HASH_NOINLINE
	FLAGS += -DSIPHASH_20B_NOINLINE
endif
endif
endif

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_snd_wnd = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -DHAS_SND_WND
endif

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_bytes_acked = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -DHAS_BYTES_ACKED
endif

C := \#include <linux/tcp.h>\nstruct tcp_info x = { .tcpi_min_rtt = 0 };
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -DHAS_MIN_RTT
endif

C := \#include <sys/random.h>\nint main(){int a=getrandom(0, 0, 0);}
ifeq ($(shell printf "$(C)" | $(CC) -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -DHAS_GETRANDOM
endif

ifeq ($(shell :|$(CC) -fstack-protector-strong -S -xc - -o - >/dev/null 2>&1; echo $$?),0)
	FLAGS += -fstack-protector-strong
endif

prefix		?= /usr/local
exec_prefix	?= $(prefix)
bindir		?= $(exec_prefix)/bin
datarootdir	?= $(prefix)/share
docdir		?= $(datarootdir)/doc/passt
mandir		?= $(datarootdir)/man
man1dir		?= $(mandir)/man1

ifeq ($(TARGET_ARCH),x86_64)
BIN := passt passt.avx2 pasta pasta.avx2 qrap
else
BIN := passt pasta qrap
endif

all: $(BIN) $(MANPAGES) docs

static: FLAGS += -static -DGLIBC_NO_STATIC_NSS
static: clean all

seccomp.h: $(PASST_SRCS) $(PASST_HEADERS)
	@ EXTRA_SYSCALLS=$(EXTRA_SYSCALLS) ./seccomp.sh $^

passt: $(PASST_SRCS) $(HEADERS)
	$(CC) $(FLAGS) $(CFLAGS) $(PASST_SRCS) -o passt $(LDFLAGS)

passt.avx2: FLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
passt.avx2: $(PASST_SRCS) $(HEADERS)
	$(CC) $(filter-out -O2,$(FLAGS) $(CFLAGS)) \
		$(PASST_SRCS) -o passt.avx2 $(LDFLAGS)

passt.avx2: passt

pasta.avx2 pasta.1 pasta: pasta%: passt%
	ln -s $< $@

qrap: $(QRAP_SRCS) passt.h
	$(CC) $(FLAGS) $(CFLAGS) $(QRAP_SRCS) -o qrap $(LDFLAGS)

valgrind: EXTRA_SYSCALLS="rt_sigprocmask rt_sigtimedwait rt_sigaction \
			  getpid gettid kill clock_gettime mmap munmap open \
			  unlink gettimeofday futex"
valgrind: FLAGS:=-g -O0 $(filter-out -O%,$(FLAGS))
valgrind: all

.PHONY: clean
clean:
	$(RM) $(BIN) *.o seccomp.h pasta.1 \
		passt.tar passt.tar.gz *.deb *.rpm \
		passt.pid README.plain.md

install: $(BIN) $(MANPAGES) docs
	mkdir -p $(DESTDIR)$(bindir) $(DESTDIR)$(man1dir)
	cp -d $(BIN) $(DESTDIR)$(bindir)
	cp -d $(MANPAGES) $(DESTDIR)$(man1dir)
	mkdir -p $(DESTDIR)$(docdir)
	cp -d README.plain.md $(DESTDIR)$(docdir)/README.md
	cp -d doc/demo.sh $(DESTDIR)$(docdir)

uninstall:
	$(RM) $(BIN:%=$(DESTDIR)$(prefix)/bin/%)
	$(RM) $(MANPAGES:%=$(DESTDIR)$(man1dir)/%)
	$(RM) $(DESTDIR)$(docdir)/README.md
	$(RM) $(DESTDIR)$(docdir)/demo.sh
	-rmdir $(DESTDIR)$(docdir)

pkgs: static
	tar cf passt.tar -P --xform 's//\/usr\/bin\//' $(BIN)
	tar rf passt.tar -P --xform 's//\/usr\/share\/man\/man1\//' \
		$(MANPAGES)
	gzip passt.tar
	EMAIL="sbrivio@redhat.com" fakeroot alien --to-deb \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=$(shell git rev-parse --short HEAD) \
		passt.tar.gz
	fakeroot alien --to-rpm --target=$(shell uname -m) \
		--description="User-mode networking for VMs and namespaces" \
		-k --version=g$(shell git rev-parse --short HEAD) passt.tar.gz

# TODO: This hack makes a "plain" Markdown version of README.md that can be
# reasonably shipped as documentation file, while the current README.md is
# definitely intended for web browser consumption. It should probably work the
# other way around: the web version should be obtained by adding HTML and
# JavaScript portions to a plain Markdown, instead. However, cgit needs to use
# a file in the git tree. Find a better way around this.
docs: README.md
	@(								\
		skip=0;							\
		while read l; do					\
			case $$l in					\
			"## Demo")	exit 0		;;		\
			"<!"*)				;;		\
			"</"*)		skip=1		;;		\
			"<"*)		skip=2		;;		\
			esac;						\
									\
			[ $$skip -eq 0 ]	&& echo "$$l";		\
			[ $$skip -eq 1 ]	&& skip=0;		\
		done < README.md;					\
	) > README.plain.md

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
# - bugprone-narrowing-conversions
# - cppcoreguidelines-narrowing-conversions
#	TODO: nice to fix eventually
#
# - cppcoreguidelines-avoid-non-const-global-variables
#	TODO: check, fix, and more in general constify wherever possible
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
#
# - readability-identifier-length
#	Complains about any identifier <3 characters, reasonable for
#	globals, pointlessly verbose for locals and parameters.

clang-tidy: $(SRCS) $(HEADERS)
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
	-bugprone-narrowing-conversions,\
	-cppcoreguidelines-narrowing-conversions,\
	-cppcoreguidelines-avoid-non-const-global-variables,\
	-altera-unroll-loops,-altera-id-dependent-backward-branch,\
	-bugprone-easily-swappable-parameters,\
	-readability-function-cognitive-complexity,\
	-altera-struct-pack-align,\
	-concurrency-mt-unsafe,\
	-readability-identifier-length \
	-config='{CheckOptions: [{key: bugprone-suspicious-string-compare.WarnOnImplicitComparison, value: "false"}]}' \
	--warnings-as-errors=* $(SRCS) -- $(filter-out -pie,$(FLAGS) $(CFLAGS))

SYSTEM_INCLUDES := /usr/include $(wildcard /usr/include/$(TARGET))
ifeq ($(shell $(CC) -v 2>&1 | grep -c "gcc version"),1)
VER := $(shell $(CC) -dumpversion)
SYSTEM_INCLUDES += /usr/lib/gcc/$(TARGET)/$(VER)/include
endif
cppcheck: $(SRCS) $(HEADERS)
	cppcheck --std=c99 --error-exitcode=1 --enable=all --force	\
	--inconclusive --library=posix --quiet				\
	$(SYSTEM_INCLUDES:%=-I%)					\
	$(SYSTEM_INCLUDES:%=--config-exclude=%)				\
	$(SYSTEM_INCLUDES:%=--suppress=*:%/*)				\
	$(SYSTEM_INCLUDES:%=--suppress=unmatchedSuppression:%/*)	\
	--suppress=objectIndex:tcp.c --suppress=objectIndex:udp.c	\
	--suppress=va_list_usedBeforeStarted:util.c			\
	--suppress=unusedFunction					\
	--suppress=knownConditionTrueFalse:conf.c			\
	--suppress=strtokCalled:conf.c --suppress=strtokCalled:qrap.c	\
	--suppress=getpwnamCalled:passt.c				\
	--suppress=localtimeCalled:pcap.c				\
	--suppress=unusedStructMember:pcap.c				\
	--suppress=funcArgNamesDifferent:util.h				\
	--suppress=unusedStructMember:dhcp.c				\
									\
	--suppress=unmatchedSuppression:conf.c				\
	--suppress=unmatchedSuppression:dhcp.c				\
	--suppress=unmatchedSuppression:passt.c				\
	--suppress=unmatchedSuppression:pcap.c				\
	--suppress=unmatchedSuppression:qrap.c				\
	--suppress=unmatchedSuppression:tcp.c				\
	--suppress=unmatchedSuppression:udp.c				\
	--suppress=unmatchedSuppression:util.c				\
	--suppress=unmatchedSuppression:util.h				\
	$(filter -D%,$(FLAGS) $(CFLAGS))				\
	.
