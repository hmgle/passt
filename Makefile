CFLAGS += -Wall -Wextra -pedantic

all: merd qrap

merd: merd.c merd.h
	$(CC) $(CFLAGS) merd.c -o merd

qrap: qrap.c merd.h
	$(CC) $(CFLAGS) qrap.o -o qrap

.PHONY: clean
clean:
	-${RM} merd qrap
