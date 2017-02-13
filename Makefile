CC = gcc
CFLAGS = -c -g -Wall -pthread 
LDFLAGS = -pthread 
TARGETS = udpgencl
OBJS = protocol.o udpgencl.o
%.o: %.c
	$(CC) $(CFLAGS) $^ -o $@
all:$(OBJS) 
	$(CC) $(OBJS) -o udpgencl

clean:
	rm -rf *.o udpgencl
