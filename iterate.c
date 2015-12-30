/* GPLv2 or later, see LICENSE */
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <ccan/take/take.h>
#include <ccan/short_types/short_types.h>
#include <ccan/opt/opt.h>
#include <ccan/htable/htable_type.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/tal/str/str.h>
#include <ccan/str/hex/hex.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
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
	struct bitcoin_block *b;
	/* So we can iterate forwards. */
	struct block *next;
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

struct utxo {
	/* txid */
	u8 tx[SHA256_DIGEST_LENGTH];

	/* Timestamp. */
	u32 timestamp;

	/* Height. */
	unsigned int height;

	/* Number of outputs. */
	u32 num_outputs;

	/* Reference count for this tx. */
	u32 unspent_outputs;

	/* Amount for each output. */
	u64 amount[];
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

static void add_utxo(struct utxo_map *utxo_map,
		     const struct block *b,
		     const struct bitcoin_transaction *t,
		     u32 txnum, off_t off)
{
	struct utxo *utxo;
	unsigned int i;

	utxo = tal_alloc_(b, sizeof(*utxo) + sizeof(utxo->amount[0])
			  * t->output_count, false, TAL_LABEL(struct utxo, ""));

	memcpy(utxo->tx, t->sha256, sizeof(utxo->tx));
	utxo->num_outputs = utxo->unspent_outputs = t->output_count;
	utxo->height = b->height;
	utxo->timestamp = b->b->timestamp;
	for (i = 0; i < utxo->num_outputs; i++)
		utxo->amount[i] = t->output[i].amount;

	utxo_map_add(utxo_map, utxo);
}

static void release_utxo(struct utxo_map *utxo_map,
			 const struct bitcoin_transaction_input *i)
{
	struct utxo *utxo;

	utxo = utxo_map_get(utxo_map, i->hash);
	if (!utxo)
		errx(1, "Unknown utxo for "SHA_FMT, SHA_VALS(i->hash));

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
		prev = block_map_get(block_map, i->b->prev_hash);
		if (!prev) {
			warnx("Block "SHA_FMT" has unknown prev "SHA_FMT,
			      SHA_VALS(i->sha),
			      SHA_VALS(i->b->prev_hash));
			/* Remove it, and all children. */
			for (; i; i = i->next)
				block_map_del(block_map, i);
			return false;
		}
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
			 struct bitcoin_transaction_output *o)
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
				printf("%u", b->b->len);
				break;
			case 'v':
				printf("%u", b->b->version);
				break;
			case 'p':
				print_hash(b->b->prev_hash);
				break;
			case 'm':
				print_hash(b->b->merkle_hash);
				break;
			case 's':
				printf("%u", b->b->timestamp);
				break;
			case 't':
				printf("%u", b->b->target);
				break;
			case 'n':
				printf("%u", b->b->nonce);
				break;
			case 'c':
				printf("%"PRIu64, b->b->transaction_count);
				break;
			case 'h':
				print_hash(b->sha);
				break;
			case 'N':
				printf("%u", b->height);
				break;
			case 'H':
				dump_block_header(b->b);
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
				print_hash(t->sha256);
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
				printf("%u", t->len);
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
				       calculate_bdd(utxo_map, t, txnum == 0, b->b->timestamp));
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
			case 'N':
				printf("%zu", i - t->input);
				break;
			case 'X':
				dump_tx_input(i);
				break;
			case 'B':
				/* Coinbase doesn't have valid input. */
				if (i - t->input != 0) {
					struct utxo *utxo = utxo_map_get(utxo_map, i->hash);
					printf("%u", utxo->height);
				} else
					printf("0");
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
			case 'X':
				dump_tx_output(o);
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
	if (!hex_decode(arg, strlen(arg), h, SHA256_DIGEST_LENGTH))
		return "Bad hex string (needs 64 hex chars)";
	return NULL;
}

int main(int argc, char *argv[])
{
	void *tal_ctx = tal(NULL, char);
	char *blockfmt = NULL, *txfmt = NULL,
		*inputfmt = NULL, *outputfmt = NULL;
	size_t i, block_count = 0;
	off_t last_discard;
	bool quiet = false, needs_utxo, read_scripts;
	unsigned long block_start = 0, block_end = -1UL;
	struct block *b, *best, *genesis = NULL, *next, *start = NULL;
	struct block_map block_map;
	char *blockdir = NULL;
	struct block_map_iter it;
	struct utxo_map utxo_map;
	unsigned progress_marks = 0;
	struct space space;
	bool use_testnet = false;
	u32 netmarker;
	u8 tip[SHA256_DIGEST_LENGTH] = { 0 },
		start_hash[SHA256_DIGEST_LENGTH] = { 0 };

	err_set_progname(argv[0]);
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "\nValid block, transaction, input or output format:\n"
			   "  <literal>: unquoted\n"
			   "  %bl: block length\n"
			   "  %bv: block version\n"
			   "  %bp: block prev hash\n"
			   "  %bm: block merkle hash\n"
			   "  %bs: block timestamp\n"
			   "  %bt: block target\n"
			   "  %bn: block nonce\n"
			   "  %bc: block transaction count\n"
			   "  %bh: block hash\n"
			   "  %bN: block height\n"
			   "  %bH: block header (hex string)\n"
			   "Valid transaction, input or output format:\n"
			   "  %th: transaction hash\n"
			   "  %tv: transaction version\n"
			   "  %ti: transaction input count\n"
			   "  %to: transaction output count\n"
			   "  %tt: transaction locktime\n"
			   "  %tl: transaction length\n"
			   "  %tN: transaction number\n"
			   "  %tF: transaction fee paid\n"
			   "  %tD: transaction bitcoin days destroyed\n"
			   "  %tX: transaction in hex\n"
			   "Valid input format:\n"
			   "  %ih: input hash\n"
			   "  %ii: input index\n"
			   "  %il: input script length\n"
			   "  %is: input script as a hex string\n"
			   "  %iN: input number\n"
			   "  %iX: input in hex\n"
			   "  %iB: input UTXO block number (0 for coinbase)\n"
			   "Valid output format:\n"
			   "  %oa: output amount\n"
			   "  %ol: output script length\n"
			   "  %os: output script as a hex string\n"
			   "  %oN: output number",
			   "  %oX: output in hex\n"
			   "Display help message");
	opt_register_arg("--block", opt_set_charp, NULL, &blockfmt,
			   "Format to print for each block");
	opt_register_arg("--tx|--transaction", opt_set_charp, NULL, &txfmt,
			   "Format to print for each transaction");
	opt_register_arg("--input", opt_set_charp, NULL, &inputfmt,
			   "Format to print for each transaction input");
	opt_register_arg("--output", opt_set_charp, NULL, &outputfmt,
			   "Format to print for each transaction output");
	opt_register_arg("--progress", opt_set_uintval, NULL,
			 &progress_marks, "Print . to stderr this many times");
	opt_register_noarg("--no-mmap", opt_set_invbool, &use_mmap,
			   "Don't mmap the block files");
	opt_register_noarg("--quiet|-q", opt_set_bool, &quiet,
			 "Don't output progress information");
	opt_register_noarg("--testnet|-t", opt_set_bool, &use_testnet,
			 "Look for testnet3 blocks");
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
	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 1)
		opt_usage_and_exit(NULL);

	if (use_testnet) {
		netmarker = 0x0709110B;
	} else {
		netmarker = 0xD9B4BEF9;
	}

	block_map_init(&block_map);
	block_fnames = block_filenames(tal_ctx, blockdir, use_testnet);

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
			struct block *old;
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
			b->b = read_bitcoin_block_header(tal_ctx, f, &off,
							 b->sha, netmarker);
			if (!b->b) {
				tal_free(b);
				break;
			}

			b->pos = off;
			old = block_map_get(&block_map, b->sha);
			if (old) {
				warnx("Already have "SHA_FMT" from %s %lu/%u",
				      SHA_VALS(b->sha),
				      block_fnames[old->filenum],
				      old->pos, old->b->len);
				block_map_delkey(&block_map, b->sha);
			}
			block_map_add(&block_map, b);
			if (is_zero(b->b->prev_hash)) {
				genesis = b;
				b->height = 0;
			}

			skip_bitcoin_transactions(b->b, block_start, &off);
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
	for (b = best; b; b = block_map_get(&block_map, b->b->prev_hash)) {
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

	/* Optimization: figure out if we need input/output scripts. */
	read_scripts = false;
	if (inputfmt && strstr(inputfmt, "%is"))
		read_scripts = true;
	if (outputfmt && strstr(outputfmt, "%os"))
		read_scripts = true;
	
	/* Optimization: figure out of we have to maintain UTXO map */
	needs_utxo = false;

	/* We need it for fee calculation (can be asked by tx, input
	 * or output) or UTXO block number */
	if (txfmt && strstr(txfmt, "%tF"))
		needs_utxo = true;
	if (txfmt && strstr(txfmt, "%tD"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%tF"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%tD"))
		needs_utxo = true;
	if (inputfmt && strstr(inputfmt, "%iB"))
		needs_utxo = true;
	if (outputfmt && strstr(outputfmt, "%tF"))
		needs_utxo = true;
	if (outputfmt && strstr(outputfmt, "%tD"))
		needs_utxo = true;

	/* Now run forwards. */
	for (b = genesis; b; b = b->next) {
		off_t off;
		struct bitcoin_transaction *tx;

		if (b == start)
			start = NULL;

		if (!start && blockfmt)
			print_format(blockfmt, NULL, b, NULL, 0, NULL, NULL);

		if (!start && progress_marks
		    && b->height % (best->height / progress_marks)
		    == (best->height / progress_marks) - 1)
			fprintf(stderr, ".");

		/* Don't read transactions if we don't have to */
		if (!txfmt && !inputfmt && !outputfmt && !needs_utxo)
			continue;

		off = b->pos;

		space_init(&space);
		tx = space_alloc_arr(&space, struct bitcoin_transaction,
				     b->b->transaction_count);
		for (i = 0; i < b->b->transaction_count; i++) {
			size_t j;
			off_t txoff = off;

			read_bitcoin_transaction(&space, &tx[i],
						 block_file(b->filenum), &off,
						 read_scripts);

			if (!start && txfmt)
				print_format(txfmt, &utxo_map, b, &tx[i], i,
					     NULL, NULL);

			if (!start && inputfmt) {
				for (j = 0; j < tx[i].input_count; j++) {
					print_format(inputfmt, &utxo_map, b,
						     &tx[i], i, &tx[i].input[j],
						     NULL);
				}
			}

			if (!start && outputfmt) {
				for (j = 0; j < tx[i].output_count; j++) {
					print_format(outputfmt, &utxo_map, b,
						     &tx[i], i, NULL,
						     &tx[i].output[j]);
				}
			}

			if (needs_utxo) {
				/* Now we can release consumed utxos;
				 * before there was a possibility of %tF */
				/* Coinbase inputs are not real */
				if (i != 0) {
					for (j = 0; j < tx[i].input_count; j++)
						release_utxo(&utxo_map,
							     &tx[i].input[j]);
				}

				/* And add this tx's outputs to utxo */
				add_utxo(&utxo_map, b, &tx[i], i, txoff);
			}
		}
	}
	return 0;
}
