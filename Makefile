CFLAGS += -Wall -Wextra -pedantic

all: merd qrap

merd: merd.c merd.h arp.c arp.h dhcp.c dhcp.h util.c util.h
	$(CC) $(CFLAGS) merd.c arp.c dhcp.c util.c -o merd

qrap: qrap.c merd.h
	$(CC) $(CFLAGS) qrap.o -o qrap

.PHONY: clean
clean:
	-${RM} merd qrap
