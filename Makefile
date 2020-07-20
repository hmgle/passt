CFLAGS += -Wall -Wextra -pedantic

all: passt qrap

passt: passt.c passt.h arp.c arp.h dhcp.c dhcp.h util.c util.h
	$(CC) $(CFLAGS) passt.c arp.c dhcp.c util.c -o passt

qrap: qrap.c passt.h
	$(CC) $(CFLAGS) qrap.c -o qrap

.PHONY: clean
clean:
	-${RM} passt *.o qrap
