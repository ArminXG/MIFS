## Makefile for mifs

PROGRAM = mifs

OBJECTS = mifs.o

INCLUDES= -I.
CFLAGS = -O2 -D_FILE_OFFSET_BITS=64 -D_REENTRANT -DFUSE_USE_VERSION=26 -g
LDFLAGS = $(CFLAGS) -pthread -lfuse -lcrypto

CC=gcc
LD=gcc

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(LD) -o $(PROGRAM) $(OBJECTS) $(LDFLAGS)

clean:
	rm -f $(PROGRAM)
	rm -f *.o

