#include <ccan/likely/likely.h>
#include <ccan/endian/endian.h>
#include <ccan/tal/tal.h>
#include <ccan/err/err.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "types.h"
#include "parse.h"

static u64 pull_varint(struct file *f, off_t *poff)
{
	u64 ret;
	u8 v[9], *p;

	if (likely(f->mmap))
		p = f->mmap + *poff;
	else {
		/* We could do a short read here, that's OK. */
		if (pread(f->fd, v, sizeof(v), *poff) < 1)
			err(1, "Pulling varint from %s offset %llu\n",
			    f->name, (long long)*poff);
		p = v;
	}

	if (*p < 0xfd) {
		ret = p[0];
		*poff += 1;
	} else if (*p == 0xfd) {
		ret = ((u64)p[2] << 8) + p[1];
		*poff += 3;
	} else if (*p == 0xfe) {
		ret = ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
		*poff += 5;
	} else {
		ret = ((u64)p[8] << 56) + ((u64)p[7] << 48)
			+ ((u64)p[6] << 40) + ((u64)p[5] << 32)
			+ ((u64)p[4] << 24) + ((u64)p[3] << 16)
			+ ((u64)p[2] << 8) + p[1];
		*poff += 9;
	}
	return ret;
}

static void pull_bytes(struct file *f, off_t *poff, void *dst, size_t num)
{
	if (likely(f->mmap))
		memcpy(dst, f->mmap + *poff, num);
	else
		file_read(f, *poff, num, dst);
	*poff += num;
}

static u32 pull_u32(struct file *f, off_t *poff)
{
	__le32 ret;

	pull_bytes(f, poff, &ret, sizeof(ret));
	return le32_to_cpu(ret);
}

static u64 pull_u64(struct file *f, off_t *poff)
{
	__le64 ret;

	pull_bytes(f, poff, &ret, sizeof(ret));
	return le64_to_cpu(ret);
}

static void pull_hash(struct file *f, off_t *poff, u8 dst[32])
{
	pull_bytes(f, poff, dst, 32);
}

static void read_input(const tal_t *ctx, struct file *f, off_t *poff,
		       struct bitcoin_transaction_input *input)
{
	pull_hash(f, poff, input->hash);
	input->index = pull_u32(f, poff);
	input->script_length = pull_varint(f, poff);
	input->script = tal_arr(ctx, u8, input->script_length);
	pull_bytes(f, poff, input->script, input->script_length);
	input->sequence_number = pull_u32(f, poff);
}

static void read_output(const tal_t *ctx, struct file *f, off_t *poff,
			struct bitcoin_transaction_output *output)
{
	output->amount = pull_u64(f, poff);
	output->script_length = pull_varint(f, poff);
	output->script = tal_arr(ctx, u8, output->script_length);
	pull_bytes(f, poff, output->script, output->script_length);
}

static void read_transaction(const tal_t *ctx, struct file *f, off_t *poff,
			     struct bitcoin_transaction *trans)
{
	size_t i;
	off_t start = *poff;
	SHA256_CTX sha256;

	trans->version = pull_u32(f, poff);
	trans->input_count = pull_varint(f, poff);
	trans->input = tal_arr(ctx,
			       struct bitcoin_transaction_input,
			       trans->input_count);
	for (i = 0; i < trans->input_count; i++)
		read_input(ctx, f, poff, trans->input + i);
	trans->output_count = pull_varint(f, poff);
	trans->output = tal_arr(ctx,
				struct bitcoin_transaction_output,
				trans->output_count);
	for (i = 0; i < trans->output_count; i++)
		read_output(ctx, f, poff, trans->output + i);
	trans->lock_time = pull_u32(f, poff);

	/* Bitcoin uses double sha (it's not quite known why...) */
	SHA256_Init(&sha256);
	if (likely(f->mmap)) {
		SHA256_Update(&sha256, f->mmap + start, *poff - start);
	} else {
		u8 *buf = tal_arr(ctx, u8, *poff - start);
		file_read(f, start, *poff - start, buf);
		SHA256_Update(&sha256, buf, *poff - start);
		tal_free(buf);
	}
	SHA256_Final(trans->sha256, &sha256);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, trans->sha256, sizeof(trans->sha256));
	SHA256_Final(trans->sha256, &sha256);
	trans->len = *poff - start;
}

/* Inefficient, but blk*.dat can have zero(?) padding. */
bool next_block_header_prefix(struct file *f, off_t *off)
{
	const u32 marker = 0xD9B4BEF9;

	while (*off + sizeof(u32) <= f->len) {
		u32 val;

		/* Inefficent, but don't expect it to be far. */
		val = pull_u32(f, off);
		*off -= 4;

		if (val == marker)
			return true;
		(*off)++;
	}
	return false;
}

struct bitcoin_block *
read_bitcoin_block_header(tal_t *ctx,
			  struct file *f, off_t *off,
			  u8 block_md[SHA256_DIGEST_LENGTH])
{
	struct bitcoin_block *block;
	SHA256_CTX sha256;
	off_t start;

	block = tal(ctx, struct bitcoin_block);
	block->D9B4BEF9 = pull_u32(f, off);
	assert(block->D9B4BEF9 == 0xd9b4bef9);
	block->len = pull_u32(f, off);

	/* Hash only covers version to nonce, inclusive. */
	start = *off;
	block->version = pull_u32(f, off);
	pull_hash(f, off, block->prev_hash);
	pull_hash(f, off, block->merkle_hash);
	block->timestamp = pull_u32(f, off);
	block->target = pull_u32(f, off);
	block->nonce = pull_u32(f, off);

	/* Bitcoin uses double sha (it's not quite known why...) */
	SHA256_Init(&sha256);
	if (likely(f->mmap)) {
		SHA256_Update(&sha256, f->mmap + start, *off - start);
	} else {
		u8 *buf = tal_arr(ctx, u8, *off - start);
		file_read(f, start, *off - start, buf);
		SHA256_Update(&sha256, buf, *off - start);
		tal_free(buf);
	}
	SHA256_Final(block_md, &sha256);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, block_md, SHA256_DIGEST_LENGTH);
	SHA256_Final(block_md, &sha256);

	block->transaction_count = pull_varint(f, off);
	block->transaction = NULL;

	return block;
}

void skip_bitcoin_transactions(struct bitcoin_block *b,
			       off_t block_start,
			       off_t *off)
{
	b->transaction = NULL;
	*off = block_start + 8 + b->len;
}

void read_bitcoin_transactions(struct bitcoin_block *b,
			       struct file *f, off_t *off)
{
	size_t i;

	b->transaction = tal_arr(b, struct bitcoin_transaction,
				 b->transaction_count);
	for (i = 0; i < b->transaction_count; i++)
		read_transaction(b, f, off, b->transaction + i);
}
