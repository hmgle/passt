CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -DRLIMIT_STACK_VAL=$(shell ulimit -s)
CFLAGS += -DPAGE_SIZE=$(shell getconf PAGE_SIZE)
CFLAGS += -DNETNS_RUN_DIR=\"/run/netns\"
CFLAGS += -DPASST_AUDIT_ARCH=AUDIT_ARCH_$(shell uname -m | tr [a-z] [A-Z])

prefix ?= /usr/local

all: passt pasta passt4netns qrap

avx2: CFLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
avx2: clean all

static: CFLAGS += -static
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
	mkdir -p $(prefix)/bin $(prefix)/man/man1
	cp -d passt pasta qrap $(prefix)/bin
	cp -d passt.1 pasta.1 qrap.1 $(prefix)/man/man1

uninstall:
	-${RM} $(prefix)/bin/passt
	-${RM} $(prefix)/bin/pasta
	-${RM} $(prefix)/bin/qrap
	-${RM} $(prefix)/man/man1/passt.1
	-${RM} $(prefix)/man/man1/pasta.1
	-${RM} $(prefix)/man/man1/qrap.1

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
