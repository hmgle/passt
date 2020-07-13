CFLAGS += -Wall -Wextra -pedantic

all: merd

merd: merd.c
	$(CC) $(CFLAGS) merd.c -o merd

.PHONY: clean
clean:
	-${RM} merd
