CFLAGS += -Wall -Wextra -pedantic
CFLAGS += -DRLIMIT_STACK_VAL=$(shell ulimit -s)

all: passt pasta passt4netns qrap

avx2: CFLAGS += -Ofast -mavx2 -ftree-vectorize -funroll-loops
avx2: clean all

static: CFLAGS += -static
static: clean all

passt: passt.c passt.h arp.c arp.h checksum.c checksum.h conf.c conf.h \
	dhcp.c dhcp.h dhcpv6.c dhcpv6.h pcap.c pcap.h ndp.c ndp.h \
	siphash.c siphash.h tap.c tap.h icmp.c icmp.h tcp.c tcp.h \
	udp.c udp.h util.c util.h
	$(CC) $(CFLAGS) passt.c arp.c checksum.c conf.c dhcp.c dhcpv6.c \
		pcap.c ndp.c siphash.c tap.c icmp.c tcp.c udp.c util.c -o passt

pasta: passt
	ln -s passt pasta

passt4netns: passt
	ln -s passt passt4netns

qrap: qrap.c passt.h
	$(CC) $(CFLAGS) -DARCH=\"$(shell uname -m)\" qrap.c -o qrap

.PHONY: clean
clean:
	-${RM} passt *.o qrap pasta passt4netns
