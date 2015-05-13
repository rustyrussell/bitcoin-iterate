/* GPLv2 or later, see LICENSE */
#include <ccan/err/err.h>
#include <ccan/tal/tal.h>
#include <ccan/take/take.h>
#include <ccan/short_types/short_types.h>
#include <ccan/opt/opt.h>
#include <ccan/htable/htable_type.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/tal/str/str.h>
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

static size_t hash_block(const u8 *key)
{
	size_t ret;

	memcpy(&ret, key, sizeof(ret));
	return ret;
}

static bool block_eq(const struct block *b, const u8 *key)
{
	return memcmp(b->sha, key, sizeof(b->sha)) == 0;
}
HTABLE_DEFINE_TYPE(struct block, keyof_block_map, hash_block, block_eq,
		   block_map);

#define CHUNK (128 * 1024 * 1024)

static bool is_zero(u8 hash[SHA256_DIGEST_LENGTH])
{
	unsigned int i;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		if (hash[i] != 0)
			return false;
	}
	return true;
}

static s32 get_height(struct block_map *block_map, struct block *b)
{
	struct block *prev;
	s32 h;

	if (b->height != -1)
		return b->height;

	prev = block_map_get(block_map, b->b->prev_hash);
	if (!prev)
		return -1;

	h = get_height(block_map, prev);
	if (h >= 0)
		return h+1;
	return h;
}

static char hexchar(unsigned int val)
{
	if (val < 10)
		return '0' + val;
	if (val < 16)
		return 'a' + val - 10;
	abort();
}

static size_t to_hex_direct(char *dest, size_t destlen,
			    const void *buf, size_t bufsize)
{
	size_t used = 0;

	/* Need room for nul terminator */
	assert(destlen > 0);

	while (destlen >= 3 && used < bufsize) {
		unsigned int c = ((const unsigned char *)buf)[used];
		*(dest++) = hexchar(c >> 4);
		*(dest++) = hexchar(c & 0xF);
		destlen -= 2;
		used++;
	}
	*dest = '\0';

	return used;
}

static void print_hash(const u8 *hash)
{
	char str[SHA256_DIGEST_LENGTH * 2 + 1];

	to_hex_direct(str, sizeof(str), hash, SHA256_DIGEST_LENGTH);
	fputs(str, stdout);
}

static void print_hex(const u8 *data, size_t len)
{
	char str[len * 2 + 1];

	to_hex_direct(str, sizeof(str), data, len);
	fputs(str, stdout);
}

/* FIXME: Speed up! */
static void print_format(const char *format,
			 struct block *b,
			 struct bitcoin_transaction *t,
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
				printf("%zu", t - b->b->transaction);
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

int main(int argc, char *argv[])
{
	void *tal_ctx = tal(NULL, char);
	char **names;
	char *blockfmt = NULL, *txfmt = NULL,
		*inputfmt = NULL, *outputfmt = NULL;
	size_t i, block_count = 0;
	off_t last_discard;
	bool mmap = true, quiet = false;
	int oflags = O_RDONLY;
	struct block *b, *best, *genesis = NULL, *next;
	struct block_map block_map;
	char *blockdir = NULL;
	struct file f;
	struct block_map_iter it;

	err_set_progname(argv[0]);
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "Valid block, transaction, input or output format:\n"
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
			   "Valid transaction, input or output format:\n"
			   "  %th: transaction hash\n"
			   "  %tv: transaction version\n"
			   "  %ti: transaction input count\n"
			   "  %to: transaction output count\n"
			   "  %tt: transaction locktime\n"
			   "  %tl: transaction length\n"
			   "  %tN: transaction number\n"
			   "Valid input format:\n"
			   "  %ih: input hash\n"
			   "  %ii: input index\n"
			   "  %il: input script length\n"
			   "  %is: input script as a hex string\n"
			   "  %iN: input number\n"
			   "Valid output format:\n"
			   "  %oa: output amount\n"
			   "  %ol: output script length\n"
			   "  %os: output script as a hex string\n"
			   "  %oN: output number",
			   "Display help message");
	opt_register_arg("--block", opt_set_charp, NULL, &blockfmt,
			   "Format to print for each block");
	opt_register_arg("--tx|--transaction", opt_set_charp, NULL, &txfmt,
			   "Format to print for each transaction");
	opt_register_arg("--input", opt_set_charp, NULL, &inputfmt,
			   "Format to print for each transaction input");
	opt_register_arg("--output", opt_set_charp, NULL, &outputfmt,
			   "Format to print for each transaction output");
	opt_register_noarg("--no-mmap", opt_set_invbool, &mmap,
			   "Don't mmap the block files");
	opt_register_noarg("--quiet|-q", opt_set_bool, &quiet,
			 "Don't output progress information");
	opt_register_arg("--blockdir", opt_set_charp, NULL, &blockdir,
			 "Block directory instead of ~/.bitcoin/blocks");
	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (!mmap)
		oflags |= O_NO_MMAP;

	if (argc != 1)
		opt_usage_and_exit(NULL);

	block_map_init(&block_map);
	names = block_filenames(tal_ctx, blockdir);
	for (i = 0; i < tal_count(names); i++) {
		off_t off = 0;

		/* new-style starts from 1, old-style starts from 0 */
		if (!names[i]) {
			if (i)
				warnx("Missing block info for %zu", i);
			continue;
		}
		file_open(&f, names[i], 0, oflags);

		if (!quiet)
			printf("bitcoin-iterate: processing %s (%zi/%zu)\n",
			       names[i], i+1, tal_count(names));

		last_discard = off = 0;
		for (;;) {
			off_t block_start;

			if (!next_block_header_prefix(&f, &off))
				break;

			block_start = off;
			b = tal(tal_ctx, struct block);
			b->filenum = i;
			b->height = -1;
			b->b = read_bitcoin_block_header(tal_ctx, &f, &off,
							 b->sha);
			if (!b->b) {
				tal_free(b);
				break;
			}

			b->pos = off;
			block_map_add(&block_map, b);
			if (is_zero(b->b->prev_hash)) {
				genesis = b;
				b->height = 0;
			} else if (genesis) {
				/* We could do this all at the end,
				 * but that means massive recursion;
				 * in practice blocks are approx in
				 * order, so this is quite
				 * efficient. */
				b->height = get_height(&block_map, b);
			}

			skip_bitcoin_transactions(b->b, block_start, &off);
			if (off > last_discard + CHUNK && f.mmap) {
				size_t len = CHUNK;
				if ((size_t)last_discard + len > f.len)
					len = f.len - last_discard;
				madvise(f.mmap + last_discard, len,
					MADV_DONTNEED);
				last_discard += len;
			}
			block_count++;
		}
		file_close(&f);
	}

	if (!genesis)
		errx(1, "Could not find a genesis block.");

	/* In case we missed some. */
	best = genesis;
	for (b = block_map_first(&block_map, &it);
	     b;
	     b = block_map_next(&block_map, &it)) {
		b->height = get_height(&block_map, b);
		if (b->height > best->height)
			best = b;
		if (b->height < 0)
			errx(1, "Block has unknown prev"
			     " %02x%02x%02x%02x%02x%02x%02x%02x"
			     "%02x%02x%02x%02x%02x%02x%02x%02x"
			     "%02x%02x%02x%02x%02x%02x%02x%02x"
			     "%02x%02x%02x%02x%02x%02x%02x%02x",
			     b->b->prev_hash[0], b->b->prev_hash[1],
			     b->b->prev_hash[2], b->b->prev_hash[3],
			     b->b->prev_hash[4], b->b->prev_hash[5],
			     b->b->prev_hash[6], b->b->prev_hash[7],
			     b->b->prev_hash[8], b->b->prev_hash[9],
			     b->b->prev_hash[10], b->b->prev_hash[11],
			     b->b->prev_hash[12], b->b->prev_hash[13],
			     b->b->prev_hash[14], b->b->prev_hash[15],
			     b->b->prev_hash[16], b->b->prev_hash[17],
			     b->b->prev_hash[18], b->b->prev_hash[19],
			     b->b->prev_hash[20], b->b->prev_hash[21],
			     b->b->prev_hash[22], b->b->prev_hash[23],
			     b->b->prev_hash[24], b->b->prev_hash[25],
			     b->b->prev_hash[25], b->b->prev_hash[26],
			     b->b->prev_hash[28], b->b->prev_hash[29],
			     b->b->prev_hash[30], b->b->prev_hash[31]);
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
		
	f.name = NULL;

	/* Now run forwards. */
	for (b = genesis; b; b = b->next) {
		off_t off;

		if (blockfmt)
			print_format(blockfmt, b, NULL, NULL, NULL);

		/* Don't read transactions if we don't have to */
		if (!txfmt && !inputfmt && !outputfmt)
			continue;

		/* A bit of caching on the file descriptor goes a long way */
		if (f.name != names[b->filenum]) {
			if (f.name)
				file_close(&f);
			file_open(&f, names[b->filenum], 0, oflags);
		}
		off = b->pos;
		read_bitcoin_transactions(b->b, &f, &off);

		for (i = 0; i < b->b->transaction_count; i++) {
			size_t j;
			struct bitcoin_transaction *tx = &b->b->transaction[i];

			if (txfmt)
				print_format(txfmt, b, tx, NULL, NULL);

			if (inputfmt) {
				for (j = 0; j < tx->input_count; j++)
					print_format(inputfmt, b, tx,
						     &tx->input[j], NULL);
			}
			if (outputfmt) {
				for (j = 0; j < tx->output_count; j++)
					print_format(outputfmt, b, tx,
						     NULL, &tx->output[j]);
			}
		}
		tal_free(b->b->transaction);
	}
	return 0;
}
