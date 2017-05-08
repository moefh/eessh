# Makefile

CC = gcc
CFLAGS = -Wall -g -iquote.
LDFLAGS =

MAIN_OBJS = main.o
COMMON_OBJS = error.o debug.o alloc.o buffer.o network.o host_key_store.o base64.o
SSH_OBJS = ssh.o ssh_constants.o debug.o hash.o cipher.o mac.o pubkey.o version_string.o stream.o connection.o kex.o kex_dh.o userauth.o channel.o
CRYPTO_OBJS = init.o random.o bignum.o oid.o dh.o sha1.o sha2.o rsa.o aes.o

LIBS = -lcrypto

OBJS = $(MAIN_OBJS) $(foreach o,$(COMMON_OBJS),common/$(o)) $(foreach o,$(SSH_OBJS),ssh/$(o)) $(foreach o,$(CRYPTO_OBJS),crypto/$(o))

.PHONY: all clean distclean test common ssh crypto 

all: eessh

clean:
	rm -f *~ *.o common/*~ common/*.o ssh/*~ ssh/*.o crypto/*~ crypto/*.o

distclean: clean
	rm -f eessh core

eessh: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

test: eessh
	valgrind -v --leak-check=full --track-origins=yes ./eessh ::1

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<
