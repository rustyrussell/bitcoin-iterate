ITERATE_OBJS := iterate.o parse.o blockfiles.o io.o dump.o
UTXOSET_OBJS := utxoset-iterate.o io.o dump.o
CCAN_OBJS := ccan-tal.o ccan-tal-path.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-htable.o ccan-hex.o ccan-tal-grab-file.o ccan-noerr.o ccan-crypto-sha256.o ccan-mem.o
CCANDIR=ccan/
# Set DECOMPRESS_PUBKEYS=1 to print p2pk outputs properly (requires OpenSSL, and -lcrypto)
CFLAGS = -O3 -flto -ggdb -I $(CCANDIR) -Wall -DDECOMPRESS_PUBKEYS=0
# If DECOMPRESS_PUBKEYS=1, set this:
#LDLIBS := -lcrypto
LDFLAGS = -O3 -flto
#CFLAGS = -ggdb -I $(CCANDIR) -Wall
BIN_DIR := /usr/local/bin

all: bitcoin-iterate utxoset-iterate doc/bitcoin-iterate.1 doc/utxoset-iterate.1

.PHONY: install

install:
	cp bitcoin-iterate utxoset-iterate $(BIN_DIR)/

$(CCAN_OBJS) $(ITERATE_OBJS) $(UTXOSET_OBJS): ccan/config.h

bitcoin-iterate: $(ITERATE_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ITERATE_OBJS) $(CCAN_OBJS) $(LDLIBS)

utxoset-iterate: $(UTXOSET_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(UTXOSET_OBJS) $(CCAN_OBJS) $(LDLIBS)

doc/bitcoin-iterate.1: doc/bitcoin-iterate.1.txt
	a2x --format=manpage $<

doc/utxoset-iterate.1: doc/utxoset-iterate.1.txt
	a2x --format=manpage $<

check:
	$(MAKE) -C test check

clean:
	$(RM) bitcoin-iterate utxoset-iterate $(ITERATE_OBJS) $(UTXOSET_OBJS) $(CCAN_OBJS)

distclean: clean
	$(RM) ccan/config.h
	$(RM) doc/bitcoin-iterate.1 doc/utxoset-iterate.1

ccan/config.h: ccan/tools/configurator/configurator
	$< > $@

ccan-tal.o: $(CCANDIR)/ccan/tal/tal.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-path.o: $(CCANDIR)/ccan/tal/path/path.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-str.o: $(CCANDIR)/ccan/tal/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-take.o: $(CCANDIR)/ccan/take/take.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-list.o: $(CCANDIR)/ccan/list/list.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-str.o: $(CCANDIR)/ccan/str/str.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt.o: $(CCANDIR)/ccan/opt/opt.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-helpers.o: $(CCANDIR)/ccan/opt/helpers.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-parse.o: $(CCANDIR)/ccan/opt/parse.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-opt-usage.o: $(CCANDIR)/ccan/opt/usage.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-htable.o: $(CCANDIR)/ccan/htable/htable.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-rbuf.o: $(CCANDIR)/ccan/rbuf/rbuf.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-hex.o: $(CCANDIR)/ccan/str/hex/hex.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-tal-grab-file.o: $(CCANDIR)/ccan/tal/grab_file/grab_file.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-noerr.o: $(CCANDIR)/ccan/noerr/noerr.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-crypto-sha256.o: $(CCANDIR)/ccan/crypto/sha256/sha256.c
	$(CC) $(CFLAGS) -c -o $@ $<
ccan-mem.o: $(CCANDIR)/ccan/mem/mem.c
	$(CC) $(CFLAGS) -c -o $@ $<
