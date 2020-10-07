/* GPLv2 or later, see LICENSE */
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/path/path.h>
#include <ccan/take/take.h>
#include <ccan/short_types/short_types.h>
#include <ccan/opt/opt.h>
#include <ccan/htable/htable_type.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/tal/str/str.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <errno.h>
#include "parse.h"
#include "blockfiles.h"
#include "io.h"
#include "dump.h"
#include "space.h"

#define SHA_FMT					   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"

#define SHA_VALS(e)							\
	e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],			\
		e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15],	\
		e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23], \
		e[24], e[25], e[26], e[27], e[28], e[29], e[30], e[31]

struct block {
	u8 sha[SHA256_DIGEST_LENGTH];
	s32 height; /* -1 for not-yet-known */
	/* Where is it */
	unsigned int filenum;
	/* Position of first transaction */
	off_t pos;
	/* So we can iterate forwards. */
	struct block *next;
	/* Bitcoin block header. */
	struct bitcoin_block bh;
};

/* Hash blocks by sha */
static const u8 *keyof_block_map(const struct block *b)
{
	return b->sha;
}

static size_t hash_sha(const u8 *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static bool block_eq(const struct block *b, const u8 *key)
{
	return memcmp(b->sha, key, sizeof(b->sha)) == 0;
}
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_sha, block_eq,
		   block_map);

#define UNKNOWN_OUTPUT 0
#define PAYMENT_OUTPUT 1
#define CHANGE_OUTPUT 2

struct utxo {
	/* txid */
	u8 tx[SHA256_DIGEST_LENGTH];

	/* Timestamp. */
	u32 timestamp;

	/* Height. */
	unsigned int height;

	/* txindex within block. */
	unsigned int txnum;

	/* Number of outputs. */
	u32 num_outputs;

	/* Reference count for this tx. */
	u32 unspent_outputs;

        /* Total amount unspent. */
        u64 unspent;
  
        /* Total amount spent. */
        u64 spent;

	/* Amount for each output. */
	u64 amount[];
  
	/* Followed by a char per output for UNKNOWN/PAYMENT/CHANGE */
};

static const u8 *keyof_utxo(const struct utxo *utxo)
{
	return utxo->tx;
}

static bool utxohash_eq(const struct utxo *utxo, const u8 *key)
{
	return memcmp(&utxo->tx, key, sizeof(utxo->tx)) == 0;
}

HTABLE_DEFINE_TYPE(struct utxo, keyof_utxo, hash_sha, utxohash_eq, utxo_map);

/* Only classify two-output txs for the moment, assuming round numbers
 * are payments.  Furthur ideas from Harold:
 *
 * 1) if the input is P2SH, and there's a P2SH and P2PKH output, then
 *    it's obvious.
 *
 * 2) lots of wallets still send change to the same public key hash as
 *    they were received originally.
 */
static void guess_output_types(const struct bitcoin_transaction *t, u8 *types)
{
	if (t->output_count == 2) {
		bool first_round = ((t->output[0].amount % 1000) == 0);
		bool second_round = ((t->output[1].amount % 1000) == 0);
		if (first_round != second_round) {
			if (first_round) {
				types[0] = PAYMENT_OUTPUT;
				types[1] = CHANGE_OUTPUT;
			} else {
				types[1] = PAYMENT_OUTPUT;
				types[0] = CHANGE_OUTPUT;
			}
			return;
		}
	}
	memset(types, UNKNOWN_OUTPUT, t->output_count);
}

static u8 *output_types(struct utxo *utxo)
{
	return (u8 *)&utxo->amount[utxo->num_outputs];
}

static bool is_unspendable(const struct bitcoin_transaction_output *o)
{
	return (o->script_length > 0 && o->script[0] == OP_RETURN);
}

static void add_utxo(const tal_t *tal_ctx,
		     struct utxo_map *utxo_map,
		     const struct block *b,
		     const struct bitcoin_transaction *t,
		     u32 txnum, off_t off)
{
	struct utxo *utxo;
	unsigned int i;
	unsigned int spend_count = 0;
	u64 initial_spent = 0;

	for (i = 0; i < t->output_count; i++) {
	  if (!is_unspendable(&t->output[i])) {
	    spend_count++;
	  } else {
	    initial_spent += t->output[i].amount;
	  }
	}

	if (spend_count == 0)
		return;

	utxo = tal_alloc_(tal_ctx, sizeof(*utxo) + (sizeof(utxo->amount[0]) + 1)
			  * t->output_count, false, TAL_LABEL(struct utxo, ""));

	memcpy(utxo->tx, t->sha256, sizeof(utxo->tx));
	utxo->num_outputs = t->output_count;
	utxo->unspent_outputs = spend_count;
	utxo->height = b->height;
	utxo->timestamp = b->bh.timestamp;
	utxo->unspent = 0;
	utxo->spent  = initial_spent;
	utxo->txnum = txnum;
	for (i = 0; i < utxo->num_outputs; i++) {
		utxo->amount[i] = t->output[i].amount;
	        utxo->unspent += t->output[i].amount;
	}
	guess_output_types(t, output_types(utxo));

	utxo_map_add(utxo_map, utxo);
}

static void release_utxo(struct utxo_map *utxo_map,
			 const struct bitcoin_transaction_input *i)
{
	struct utxo *utxo;

	utxo = utxo_map_get(utxo_map, i->hash);
	if (!utxo)
		errx(1, "Unknown utxo for "SHA_FMT, SHA_VALS(i->hash));

	utxo->spent += utxo->amount[i->index];

	if (--utxo->unspent_outputs == 0) {
		utxo_map_del(utxo_map, utxo);
		tal_free(utxo);
	}
}

#define CHUNK (128 * 1024 * 1024)

static bool use_mmap = true;
static char **block_fnames;

/* Cache file opens. */
static struct file *block_file(unsigned int index)
{
#define NUM_BLOCKFILES 2
	static struct file f[NUM_BLOCKFILES];
	static size_t next;
	size_t i;

	for (i = 0; i < NUM_BLOCKFILES; i++) {
		if (f[i].name == block_fnames[index])
			return f+i;
	}

	/* Kick one out. */
	i = next;
	if (f[i].name)
		file_close(&f[i]);

	file_open(&f[i], block_fnames[index], 0,
		  O_RDONLY | (use_mmap ? 0 : O_NO_MMAP));
	next++;
	if (next == NUM_BLOCKFILES)
		next = 0;
	return f + i;
}


static bool is_zero(u8 hash[SHA256_DIGEST_LENGTH])
{
	unsigned int i;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (hash[i] != 0)
			return false;
	}
	return true;
}

#define MAXU32 (0xFFFFFFFFul)
static void mul_and_add(u64 *over, u64 *base, u64 l, u64 r)
{
	u64 l_h = l >> 32,
	    r_h = r >> 32,
	    l_l = l & MAXU32,
	    r_l = r & MAXU32;
	u64 a = *over, b = 0, c = *base;
	b = (c >> 32); c &= MAXU32;

	assert (0 <= b && b <= MAXU32);
	assert (0 <= c && c <= MAXU32);

	c += l_l * r_l;
	b += (c >> 32); c &= MAXU32;
	a += (b >> 32); b &= MAXU32;

	b += l_h * r_l;
	a += (b >> 32); b &= MAXU32;

	b += l_l * r_h;
	a += (b >> 32); b &= MAXU32;

	a += l_h * r_h;  /* realistically r_h=0 so this is a no op */

	*over = a;
	*base = (b << 32) | c;
}

static bool set_height(struct block_map *block_map, struct block *b)
{
	struct block *i, *prev;

	if (b->height != -1)
		return true;

	i = b;
	do {
		prev = block_map_get(block_map, i->bh.prev_hash);
		if (!prev)
			return false;
		prev->next = i;
		i = prev;
	} while (i->height == -1);

	/* Now iterate forward, setting height for all. */
	b->next = NULL;
	for (i = prev->next; i; i = i->next) {
		i->height = prev->height + 1;
		prev = i;
	}
	return true;
}

/* This is kind of silly, since they can print it and sum it
 * themselves.  But convenient though... */
static s64 calculate_fees(const struct utxo_map *utxo_map,
			  const struct bitcoin_transaction *t,
			  bool is_coinbase)
{
	size_t i;
	s64 total = 0;

	if (is_coinbase)
		goto sum_outputs;
	
	for (i = 0; i < t->input_count; i++) {
		struct utxo *utxo;

		utxo = utxo_map_get(utxo_map, t->input[i].hash);
		if (!utxo)
			errx(1, "Unknown utxo for "SHA_FMT,
			     SHA_VALS(t->input[i].hash));

		if (t->input[i].index >= utxo->num_outputs)
			errx(1, "Invalid utxo output %u for "SHA_FMT,
			     t->input[i].index, SHA_VALS(t->input[i].hash));
		total += utxo->amount[t->input[i].index];
	}

sum_outputs:
	for (i = 0; i < t->output_count; i++)
		total -= t->output[i].amount;

	if (!is_coinbase && total < 0)
		errx(1, "Invalid total %"PRIi64" for "SHA_FMT,
		     total, SHA_VALS(t->sha256));
	return total;
}

static s64 calculate_bdc(const struct utxo *u, u32 timestamp)
{
        u32 age;
	u64 total_over = 0;
	u64 total_base = 0;
	age = ((timestamp > u->timestamp) ? (timestamp - u->timestamp) : 0);
	mul_and_add(&total_over, &total_base, u->unspent, age);
	/* we have satoshi-seconds, convert to satoshi days by dividing by */
	/* 86400 */
	if (total_over >= 86400/2)
		return -2; /* overflow! */
	return (((total_over << 47) / 86400) << 17) + (total_base / 86400);
}

static s64 calculate_bdd(const struct utxo_map *utxo_map,
			  const struct bitcoin_transaction *t,
			  bool is_coinbase, u32 timestamp)
{
	size_t i;
	u64 total_over = 0;
	u64 total_base = 0;

	if (is_coinbase)
		return 0;

	for (i = 0; i < t->input_count; i++) {
		struct utxo *utxo;

		utxo = utxo_map_get(utxo_map, t->input[i].hash);
		if (!utxo)
			errx(1, "Unknown utxo for "SHA_FMT,
			     SHA_VALS(t->input[i].hash));

		if (t->input[i].index >= utxo->num_outputs)
			errx(1, "Invalid utxo output %u for "SHA_FMT,
			     t->input[i].index, SHA_VALS(t->input[i].hash));


		mul_and_add(&total_over, &total_base,
		            utxo->amount[t->input[i].index],
		            timestamp > utxo->timestamp ? timestamp - utxo->timestamp : 0);
	}

	/* we have satoshi-seconds, convert to satoshi days by dividing by
	 * 86400 */
	if (total_over >= 86400/2)
		return -2; /* overflow! */
	return (((total_over << 47) / 86400) << 17) + (total_base / 86400);
}

/* FIXME: Speed up! */
static void print_format(const char *format,
			 const struct utxo_map *utxo_map,
			 struct block *b,
			 struct bitcoin_transaction *t,
			 size_t txnum,
			 struct bitcoin_transaction_input *i,
			 struct bitcoin_transaction_output *o,
			 struct utxo *u)
{
	const char *c;

	for (c = format; *c; c++) {
		if (*c != '%') {
			fputc(*c, stdout);
			continue;
		}

		switch (c[1]) {
		case 'b':
			switch (c[2]) {
			case 'l':
				printf("%u", b->bh.len);
				break;
			case 'v':
				printf("%u", b->bh.version);
				break;
			case 'p':
				print_reversed_hash(b->bh.prev_hash);
				break;
			case 'm':
				print_hash(b->bh.merkle_hash);
				break;
			case 's':
				printf("%u", b->bh.timestamp);
				break;
			case 't':
				printf("%u", b->bh.target);
				break;
			case 'n':
				printf("%u", b->bh.nonce);
				break;
			case 'c':
				printf("%"PRIu64, b->bh.transaction_count);
				break;
			case 'h':
				print_reversed_hash(b->sha);
				break;
			case 'N':
				printf("%u", b->height);
				break;
			case 'H':
				dump_block_header(&b->bh);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 't':
			if (!t)
				goto bad_fmt;
			switch (c[2]) {
			case 'h':
				print_reversed_hash(t->sha256);
				break;
			case 'v':
				printf("%u", t->version);
				break;
			case 'i':
				printf("%"PRIu64, t->input_count);
				break;
			case 'o':
				printf("%"PRIu64, t->output_count);
				break;
			case 't':
				printf("%u", t->lock_time);
				break;
			case 'l':
				printf("%u", (t->total_len + 3*t->non_swlen + 3) / 4);
				break;
			case 'w':
				printf("%u", t->total_len + 3*t->non_swlen);
				break;
			case 'W':
				printf("%u", t->total_len - t->non_swlen);
				break;
			case 'N':
				printf("%zu", txnum);
				break;
			case 'F':
				printf("%"PRIi64,
				       calculate_fees(utxo_map, t, txnum == 0));
				break;
			case 'D':
				printf("%"PRIi64,
				       calculate_bdd(utxo_map, t, txnum == 0, b->bh.timestamp));
				break;
			case 'X':
				dump_tx(t);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 'i':
			if (!i)
				goto bad_fmt;
			switch (c[2]) {
			case 'h':
				print_hash(i->hash);
				break;
			case 'i':
				printf("%u", i->index);
				break;
			case 'l':
				printf("%"PRIu64, i->script_length);
				break;
			case 's':
				print_hex(i->script, i->script_length);
				break;
			case 'q':
				printf("%u", i->sequence_number);
				break;
			case 'N':
				printf("%zu", i - t->input);
				break;
			case 'X':
				dump_tx_input(i);
				break;
			case 'a':
				/* Coinbase doesn't have valid input. */
				if (txnum != 0) {
					struct utxo *utxo = utxo_map_get(utxo_map, i->hash);
					printf("%"PRIu64, utxo->amount[i->index]);
				} else
					printf("0");
				break;
			case 'B':
				/* Coinbase doesn't have valid input. */
				if (txnum != 0) {
					struct utxo *utxo = utxo_map_get(utxo_map, i->hash);
					printf("%u", utxo->height);
				} else
					printf("0");
				break;
			case 'T':
				/* Coinbase doesn't have valid input. */
				if (txnum != 0) {
					struct utxo *utxo = utxo_map_get(utxo_map, i->hash);
					printf("%u", utxo->txnum);
				} else
					printf("-1");
				break;
			case 'p':
				/* Coinbase doesn't have valid input. */
				if (txnum != 0) {
					struct utxo *utxo = utxo_map_get(utxo_map, i->hash);
					printf("%u", output_types(utxo)[i->index]);
				} else
					printf("%u", UNKNOWN_OUTPUT);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 'o':
			if (!o)
				goto bad_fmt;
			switch (c[2]) {
			case 'a':
				printf("%"PRIu64, o->amount);
				break;
			case 'l':
				printf("%"PRIu64, o->script_length);
				break;
			case 's':
				print_hex(o->script, o->script_length);
				break;
			case 'N':
				printf("%zu", o - t->output);
				break;
			case 'U':
				printf("%u", is_unspendable(o));
				break;
			case 'X':
				dump_tx_output(o);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 'u':
			if (!u)
				goto bad_fmt;
			switch (c[2]) {
			case 'h':
			        print_hash(u->tx);
			        break;
			case 't':
				printf("%u", u->timestamp);
				break;
			case 'c':
				printf("%u", u->num_outputs);
				break;
			case 'u':
				printf("%u", u->unspent_outputs);
				break;
			case 's':
				printf("%u", u->num_outputs - u->unspent_outputs);
				break;
			case 'U':
				printf("%"PRIu64, u->unspent);
				break;
			case 'S':
				printf("%"PRIu64, u->spent);
				break;
			case 'C':
				printf("%"PRIi64,
				       calculate_bdc(u, b->bh.timestamp));
				break;
			default:
				goto bad_fmt;
			}
			break;
		}

		/* Skip first two escape letters; loop will skip next */
		c += 2;
	}
	fputc('\n', stdout);
	return;
	
bad_fmt:
	errx(1, "Bad %s format %.3s",
	     i ? "input" : o ? "output" : t ? "transaction" : "block",
	     c);
}

static char *opt_set_hash(const char *arg, u8 *h)
{
	size_t i;
	u8 hash[SHA256_DIGEST_LENGTH];

	if (!hex_decode(arg, strlen(arg), hash, SHA256_DIGEST_LENGTH))
		return "Bad hex string (needs 64 hex chars)";

	/* Backwards endian is the Bitcoin Way */
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		h[i] = hash[SHA256_DIGEST_LENGTH-i-1];

	return NULL;
}

static bool read_utxo_cache(const tal_t *ctx,
			    struct utxo_map *utxo_map,
			    const char *cachedir,
			    const u8 *blockid)
{
	char blockhex[hex_str_size(SHA256_DIGEST_LENGTH)];
	char *file;
	char *contents;
	size_t bytes;

	hex_encode(blockid, SHA256_DIGEST_LENGTH, blockhex, sizeof(blockhex));
	file = path_join(NULL, cachedir, blockhex);
	contents = grab_file(file, file);
	if (!contents) {
		tal_free(file);
		return false;
	}

	bytes = tal_count(contents) - 1;

	/* Size UTXO appropriately immediately (slightly oversize). */
	utxo_map_clear(utxo_map);
	utxo_map_init_sized(utxo_map, bytes / sizeof(struct utxo));

	while (bytes) {
		struct utxo *utxo;
		size_t size = sizeof(*utxo) + sizeof(utxo->amount[0])
			* ((struct utxo *)contents)->num_outputs;

		/* Truncated? */
		if (size > bytes) {
			warnx("Truncated cache file %s: deleting", file);
			unlink(file);
			tal_free(file);
			return false;
		}
		utxo = tal_alloc_(ctx, size, false, TAL_LABEL(struct utxo, ""));
		memcpy(utxo, contents, size);
		utxo_map_add(utxo_map, utxo);

		contents += size;
		bytes -= size;
	}
	tal_free(file);
	return true;
}

static void write_utxo_cache(const struct utxo_map *utxo_map,
			     const char *cachedir,
			     const u8 *blockid)
{
	char *file;
	char blockhex[hex_str_size(SHA256_DIGEST_LENGTH)];
	struct utxo_map_iter it;
	struct utxo *utxo;
	int fd;

	hex_encode(blockid, SHA256_DIGEST_LENGTH, blockhex, sizeof(blockhex));
	file = path_join(NULL, cachedir, blockhex);

	fd = open(file, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0) {
		if (errno != EEXIST) 
			err(1, "Creating '%s' for writing", file);
		tal_free(file);
		return;
	}

	for (utxo = utxo_map_first(utxo_map, &it);
	     utxo;
	     utxo = utxo_map_next(utxo_map, &it)) {
		size_t size = sizeof(*utxo) + sizeof(utxo->amount[0])
			* utxo->num_outputs;
		if (write(fd, utxo, size) != size)
			errx(1, "Short write to %s", file);
	}
}

/* Returns true if we know the height (ie. complete chain from genesis) */
static bool add_block(struct block_map *block_map, struct block *b,
		      struct block **genesis, size_t *num_misses)
{
	struct block *prev, *old = block_map_get(block_map, b->sha);

	if (old) {
		warnx("Already have "SHA_FMT" from %s %lu/%u",
		      SHA_VALS(b->sha),
		      block_fnames[old->filenum],
		      old->pos, old->bh.len);
		block_map_delkey(block_map, b->sha);
	}
	block_map_add(block_map, b);
	if (is_zero(b->bh.prev_hash)) {
		*genesis = b;
		b->height = 0;
		*num_misses = 0;
		return true;
	}

	/* Optimistically search for previous: blocks usually in rough order */
	prev = block_map_get(block_map, b->bh.prev_hash);
	if (prev) {
		if (prev->height != -1) {
			b->height = prev->height + 1;
			*num_misses = 0;
			return true;
		}

		/* Every 1000 blocks we didn't get height for, try recursing. */
		if ((*num_misses)++ % 1000 == 0) {
			if (set_height(block_map, b)) {
				*num_misses = 0;
				return true;
			}
		}
	}
	return false;
}

static void read_blockcache(const tal_t *tal_ctx,
			    bool quiet,
			    struct block_map *block_map,
			    const char *blockcache,
			    struct block **genesis)
{
	size_t i, num, num_misses = 0;
	struct block *b = grab_file(tal_ctx, blockcache);

	if (!b)
		err(1, "Could not read %s", blockcache);

	num = (tal_count(b) - 1) / sizeof(*b);
	if (!quiet)
		printf("Adding %zu blocks from cache\n", num);

	block_map_init_sized(block_map, num);
	for (i = 0; i < num; i++)
		add_block(block_map, &b[i], genesis, &num_misses);
}

static void write_blockcache(struct block_map *block_map,
			     const char *cachedir,
			     const char *blockcache)
{
	struct block_map_iter it;
	struct block *b;
	int fd;

	fd = open(blockcache, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if (fd < 0 && errno == ENOENT) {
		if (mkdir(cachedir, 0700) != 0)
			err(1, "Creating cachedir '%s'", cachedir);
		fd = open(blockcache, O_WRONLY|O_CREAT|O_EXCL, 0600);
	}
	if (fd < 0)
		err(1, "Creating '%s' for writing", blockcache);

	for (b = block_map_first(block_map, &it);
	     b;
	     b = block_map_next(block_map, &it)) {
		if (write(fd, b, sizeof(*b)) != sizeof(*b))
			err(1, "Short write to %s", blockcache);
	}
	close(fd);
}

int main(int argc, char *argv[])
{
	void *tal_ctx = tal(NULL, char);
	char *blockfmt = NULL, *txfmt = NULL,
	  *inputfmt = NULL, *outputfmt = NULL, *utxofmt = NULL, *cachedir = NULL;
	size_t i, block_count = 0;
	off_t last_discard;
	bool quiet = false, needs_utxo, needs_fee;
	unsigned long block_start = 0, block_end = -1UL;
	struct block *b, *best, *genesis = NULL, *next, *start = NULL;
	struct block_map block_map;
	char *blockdir = NULL, *blockcache = NULL;
	struct block_map_iter it;
	struct utxo_map utxo_map;
	unsigned progress_marks = 0;
	struct space space;
	size_t num_misses = 0;
	bool use_testnet = false;
	bool use_regtest = false;
	bool use_signet = false;
	u32 netmarker;
	u8 tip[SHA256_DIGEST_LENGTH] = { 0 },
		start_hash[SHA256_DIGEST_LENGTH] = { 0 };
	unsigned int utxo_period = 144;
	enum networks network = MAIN;

	err_set_progname(argv[0]);
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "\nValid block, transaction, input, output, and utxo format:\n"
			   "  <literal>: unquoted\n"
			   "  %bl: block length\n"
			   "  %bv: block version\n"
			   "  %bp: block prev hash (big-endian)\n"
			   "  %bm: block merkle hash\n"
			   "  %bs: block timestamp\n"
			   "  %bt: block target\n"
			   "  %bn: block nonce\n"
			   "  %bc: block transaction count\n"
			   "  %bh: block hash (big-endian)\n"
			   "  %bN: block height\n"
			   "  %bH: block header (hex string)\n"
			   "Valid transaction, input or output format:\n"
			   "  %th: transaction hash (big-endian)\n"
			   "  %tv: transaction version\n"
			   "  %ti: transaction input count\n"
			   "  %to: transaction output count\n"
			   "  %tt: transaction locktime\n"
			   "  %tl: transaction length (in vbytes)\n"
			   "  %tw: transaction weight (in sipa)\n"
			   "  %tW: transaction witness length (in bytes)\n"
			   "  %tN: transaction number\n"
			   "  %tF: transaction fee paid\n"
			   "  %tD: transaction bitcoin days destroyed\n"
			   "  %tX: transaction in hex\n"
			   "Valid input format:\n"
			   "  %ia: input amount\n"
			   "  %ih: input hash\n"
			   "  %ii: input index\n"
			   "  %il: input script length\n"
			   "  %is: input script as a hex string\n"
			   "  %iq: input nSequence\n"
			   "  %iN: input number\n"
			   "  %iX: input in hex\n"
			   "  %iB: input UTXO block number (0 for coinbase)\n"
			   "  %iT: input UTXO transaction number (-1 for coinbase)\n"
			   "  %ip: input payment guess: same ("
			    stringify(CHANGE_OUTPUT) ") or different ("
			    stringify(PAYMENT_OUTPUT) ") owner, or ("
			    stringify(UNKNOWN_OUTPUT) ") unknown\n"
			   "Valid output format:\n"
			   "  %oa: output amount\n"
			   "  %ol: output script length\n"
			   "  %os: output script as a hex string\n"
			   "  %oN: output number\n"
			   "  %oU: output is unspendable (0 if spendable)\n"
			   "  %oX: output in hex\n"
			   "Valid utxo format:\n"
			   "  %uh: utxo transaction hash\n"
			   "  %ut: utxo timestamp\n"
			   "  %uc: utxo output count\n"
			   "  %uu: utxo unspent output count\n"
			   "  %us: utxo spent output count\n"
			   "  %uU: utxo unspent amount\n"
			   "  %uS: utxo spent amount\n"
			   "  %uC: utxo bitcoin days created\n",
			   "Display help message");
	opt_register_arg("--block", opt_set_charp, NULL, &blockfmt,
			   "Format to print for each block");
	opt_register_arg("--tx|--transaction", opt_set_charp, NULL, &txfmt,
			   "Format to print for each transaction");
	opt_register_arg("--input", opt_set_charp, NULL, &inputfmt,
			   "Format to print for each transaction input");
	opt_register_arg("--output", opt_set_charp, NULL, &outputfmt,
			   "Format to print for each transaction output");
	opt_register_arg("--utxo", opt_set_charp, NULL, &utxofmt,
			   "Format to print for each UTXO");
	opt_register_arg("--utxo-period", opt_set_uintval, NULL,
			 &utxo_period, "Loop over UTXOs every this many blocks");
	opt_register_arg("--progress", opt_set_uintval, NULL,
			 &progress_marks, "Print . to stderr this many times");
	opt_register_noarg("--no-mmap", opt_set_invbool, &use_mmap,
			   "Don't mmap the block files");
	opt_register_noarg("--quiet|-q", opt_set_bool, &quiet,
			 "Don't output progress information");
	opt_register_noarg("--testnet|-t", opt_set_bool, &use_testnet,
			 "Look for testnet3 blocks");
	opt_register_noarg("--regtest|-r", opt_set_bool, &use_regtest,
			 "Look for regtest blocks");
	opt_register_noarg("--signet|-s", opt_set_bool, &use_signet,
			 "Look for signet blocks");
	opt_register_arg("--blockdir", opt_set_charp, NULL, &blockdir,
			 "Block directory instead of ~/.bitcoin/[testnet3/]blocks");
	opt_register_arg("--end-hash", opt_set_hash, NULL, tip,
			 "Best blockhash to use instead of longest chain.");
	opt_register_arg("--start-hash", opt_set_hash, NULL, start_hash,
			 "Blockhash to start at instead of genesis.");
	opt_register_arg("--start", opt_set_ulongval, NULL, &block_start,
			 "Block number to start instead of genesis.");
	opt_register_arg("--end", opt_set_ulongval, NULL, &block_end,
			 "Block number to end at instead of longest chain.");
	opt_register_arg("--cache", opt_set_charp, NULL, &cachedir,
			 "Cache for multiple runs.");
	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 1)
		opt_usage_and_exit(NULL);

	if (use_testnet) {
		netmarker = 0x0709110B;
		network = TESTNET3;
	} else if (use_regtest) {
		netmarker = 0xDAB5BFFA;
		network = REGTEST;
	} else if (use_signet) {
		netmarker = 0x40CF030A;
		network = SIGNET;
	} else {
		netmarker = 0xD9B4BEF9;
		network = MAIN;
	}

	block_fnames = block_filenames(tal_ctx, blockdir, network);

	if (cachedir && tal_count(block_fnames)) {
		size_t last = tal_count(block_fnames) - 1;
		struct stat cache_st, block_st;

		/* Cache matches name of final block file */
		blockcache = path_join(tal_ctx, cachedir,
				       path_basename(tal_ctx,
						     block_fnames[last]));

		if (stat(block_fnames[last], &block_st) != 0)
			errx(1, "Could not stat %s", block_fnames[last]);
		if (stat(blockcache, &cache_st) == 0) {
			if (block_st.st_mtime >= cache_st.st_mtime) {
				if (!quiet)
					printf("%s is newer than cache\n",
					       block_fnames[last]);
			} else {
				read_blockcache(tal_ctx, quiet,
						&block_map, blockcache,
						&genesis);
				goto check_genesis;
			}
		}
	}
	block_map_init(&block_map);

	for (i = 0; i < tal_count(block_fnames); i++) {
		off_t off = 0;

		/* new-style starts from 1, old-style starts from 0 */
		if (!block_fnames[i]) {
			if (i)
				warnx("Missing block info for %zu", i);
			continue;
		}

		if (!quiet)
			printf("bitcoin-iterate: processing %s (%zi/%zu)\n",
			       block_fnames[i], i+1, tal_count(block_fnames));

		last_discard = off = 0;
		for (;;) {
			off_t block_start;
			struct file *f = block_file(i);

			block_start = off;
			if (!next_block_header_prefix(f, &off, netmarker)) {
				if (off != block_start)
					warnx("Skipped %lu at end of %s",
					      off - block_start, block_fnames[i]);
				break;
			}
			if (off != block_start)
				warnx("Skipped %lu@%lu in %s",
				      off - block_start, block_start,
				      block_fnames[i]);

			block_start = off;
			b = tal(tal_ctx, struct block);
			b->filenum = i;
			b->height = -1;
			if (!read_bitcoin_block_header(&b->bh, f, &off,
						       b->sha, netmarker)) {
				tal_free(b);
				break;
			}

			b->pos = off;
			if (add_block(&block_map, b, &genesis, &num_misses)) {
				/* Go 100 past the block they asked
				 * for (avoid minor forks) */
				if (block_end != -1UL && b->height > block_end + 100)
					goto check_genesis;
			}

			skip_bitcoin_transactions(&b->bh, block_start, &off);
			if (off > last_discard + CHUNK && f->mmap) {
				size_t len = CHUNK;
				if ((size_t)last_discard + len > f->len)
					len = f->len - last_discard;
				madvise(f->mmap + last_discard, len,
					MADV_DONTNEED);
				last_discard += len;
			}
			block_count++;
		}
	}

	if (blockcache) {
		write_blockcache(&block_map, cachedir, blockcache);
		if (!quiet)
			printf("Wrote block cache to %s\n", blockcache);
	}

check_genesis:
	if (!genesis)
		errx(1, "Could not find a genesis block.");

	/* Link up prevs. */
	best = genesis;
	for (b = block_map_first(&block_map, &it);
	     b;
	     b = block_map_next(&block_map, &it)) {
		set_height(&block_map, b);
		if (b->height > best->height)
			best = b;
	}

	/* If they told us a tip, that overrides. */
	if (!is_zero(tip)) {
		best = block_map_get(&block_map, tip);
		if (!best)
			errx(1, "Unknown --end block "SHA_FMT, SHA_VALS(tip));
	}
			
	/* If they told us a start, make sure it exists. */
	if (!is_zero(start_hash)) {
		start = block_map_get(&block_map, start_hash);
		if (!start)
			errx(1, "Unknown --start block "SHA_FMT,
			     SHA_VALS(start_hash));
	}

	if (!quiet)
		printf("bitcoin-iterate: best block height: %u (of %zu)\n",
		       best->height, block_count);

	/* Now iterate down from best, setting next pointers. */
	next = NULL;
	for (b = best; b; b = block_map_get(&block_map, b->bh.prev_hash)) {
		b->next = next;
		next = b;
	}

	/* If they told us to end somewhere, do that. */
	if (block_end != -1UL) {
		for (b = genesis; b->height != block_end; b = b->next) {
			if (!b->next)
				errx(1, "No block end %lu found", block_end);
		}
		best = b;
		b->next = NULL;
	}

	/* Similar with start block */
	if (block_start != 0) {
		for (b = genesis; b->height != block_start; b = b->next) {
			if (!b->next)
				errx(1, "No block start %lu found", block_start);
		}
		start = b;
	}

	utxo_map_init(&utxo_map);

	/* Optimization: figure out of we have to maintain UTXO map */
	needs_utxo = false;

	/* We need it for fee calculation, UTXO block number, or
	 * bitcoin days created/destroyed.  Can be asked by tx, input,
	 * output, or UTXO. */
	if (txfmt && strstr(txfmt, "%tF"))
		needs_utxo = true;
	if (txfmt && strstr(txfmt, "%tD"))
		needs_utxo = true;
	if (blockfmt && strstr(blockfmt, "%bD"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%tF"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%tD"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%iB"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%iT"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%ia"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%ip"))
		needs_utxo = true;
	if (outputfmt && strstr(outputfmt, "%tF"))
		needs_utxo = true;
	if (outputfmt && strstr(outputfmt, "%tD"))
		needs_utxo = true;
	if (utxofmt)
		needs_utxo = true;
	
	needs_fee = needs_utxo;

	/* Do we have cache utxo? */
	if (cachedir && start && needs_utxo) {
		if (read_utxo_cache(tal_ctx, &utxo_map, cachedir, start->sha)) {
			needs_fee = false;
			if (!quiet)
				printf("Found valid UTXO cache\n");
		} else if (!quiet)
			printf("Did not find valid UTXO cache\n");
	}

	/* Now run forwards. */
	for (b = genesis; b; b = b->next) {
		off_t off;
		struct bitcoin_transaction *tx;

		if (b == start) {
			/* Are we UTXO caching? */
			if (cachedir && needs_utxo) {
				if (needs_fee) {
					/* Save cache for next time. */
					write_utxo_cache(&utxo_map, cachedir,
							 b->sha);
					if (!quiet)
						printf("Wrote UTXO cache\n");
				} else
					/* We loaded cache, now we calc fee. */
					needs_fee = true;
			}
			start = NULL;
		}

		if (!start && blockfmt)
		    print_format(blockfmt, &utxo_map, b, NULL, 0, NULL, NULL, NULL);

		if (!start && progress_marks
		    && b->height % (best->height / progress_marks)
		    == (best->height / progress_marks) - 1)
			fprintf(stderr, ".");

		/* Don't read transactions if we don't have to */
		if (!txfmt && !inputfmt && !outputfmt && !utxofmt)
			continue;

		/* If we haven't started and don't need to gather UTXO, skip */
		if (start && !needs_fee)
			continue;
		
		off = b->pos;

		space_init(&space);
		tx = space_alloc_arr(&space, struct bitcoin_transaction,
				     b->bh.transaction_count);
		for (i = 0; i < b->bh.transaction_count; i++) {
			size_t j;
			off_t txoff = off;

			read_bitcoin_transaction(&space, &tx[i],
						 block_file(b->filenum), &off);

			if (!start && txfmt)
				print_format(txfmt, &utxo_map, b, &tx[i], i,
					     NULL, NULL, NULL);

			if (!start && inputfmt) {
				for (j = 0; j < tx[i].input_count; j++) {
					print_format(inputfmt, &utxo_map, b,
						     &tx[i], i, &tx[i].input[j],
						     NULL, NULL);
				}
			}

			if (!start && outputfmt) {
				for (j = 0; j < tx[i].output_count; j++) {
					print_format(outputfmt, &utxo_map, b,
						     &tx[i], i, NULL,
						     &tx[i].output[j], NULL);
				}
			}

			if (needs_fee) {
				/* Now we can release consumed utxos;
				 * before there was a possibility of %tF */
				/* Coinbase inputs are not real */
				if (i != 0) {
					for (j = 0; j < tx[i].input_count; j++)
						release_utxo(&utxo_map,
							     &tx[i].input[j]);
				}

				/* And add this tx's outputs to utxo */
				add_utxo(tal_ctx, &utxo_map, b, &tx[i], i, txoff);
			}
		}
		if (utxofmt && ((b->height % utxo_period) == 0)) {
		  struct utxo_map_iter it;
		  struct utxo *utxo;
		  for (utxo = utxo_map_first(&utxo_map, &it);
		       utxo;
		       utxo = utxo_map_next(&utxo_map, &it)) {
		    print_format(utxofmt, &utxo_map, b, NULL, 0, NULL, NULL, utxo);
		  }
		}
	}
	return 0;
}
