CFLAGS += -Wall -Wextra -pedantic

all: passt qrap

passt: passt.c passt.h arp.c arp.h dhcp.c dhcp.h ndp.c ndp.h tap.c tap.h tcp.c tcp.h udp.c udp.h util.c util.h
	$(CC) $(CFLAGS) passt.c arp.c dhcp.c ndp.c tap.c tcp.c udp.c util.c -o passt

qrap: qrap.c passt.h
	$(CC) $(CFLAGS) qrap.c -o qrap

.PHONY: clean
clean:
	-${RM} passt *.o qrap
