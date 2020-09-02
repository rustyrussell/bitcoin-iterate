ITERATE_OBJS := iterate.o parse.o blockfiles.o io.o dump.o sha256.o
#CCAN_OBJS := ccan-asort.o ccan-breakpoint.o ccan-tal.o ccan-tal-path.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-htable.o ccan-rbuf.o
CCAN_OBJS := ccan-tal.o ccan-tal-path.o ccan-tal-str.o ccan-take.o ccan-list.o ccan-str.o ccan-opt-helpers.o ccan-opt.o ccan-opt-parse.o ccan-opt-usage.o ccan-htable.o ccan-rbuf.o ccan-hex.o ccan-tal-grab-file.o ccan-noerr.o
CCANDIR=ccan/
CFLAGS = -O3 -flto -ggdb -I $(CCANDIR) -Wall
LDFLAGS = -O3 -flto
#CFLAGS = -ggdb -I $(CCANDIR) -Wall
LDLIBS :=
BIN_DIR := /usr/local/bin

all: bitcoin-iterate doc/bitcoin-iterate.1

.PHONY: install

install:
	cp bitcoin-iterate $(BIN_DIR)/bitcoin-iterate

$(CCAN_OBJS) $(ITERATE_OBJS): ccan/config.h

bitcoin-iterate: $(ITERATE_OBJS) $(CCAN_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(ITERATE_OBJS) $(CCAN_OBJS) $(LDLIBS)

doc/bitcoin-iterate.1: doc/bitcoin-iterate.1.txt
	a2x --format=manpage $<

check:
	$(MAKE) -C test check

clean:
	$(RM) bitcoin-iterate $(ITERATE_OBJS) $(CCAN_OBJS)

distclean: clean
	$(RM) ccan/config.h
	$(RM) doc/bitcoin-iterate.1

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
