#include <ccan/likely/likely.h>
#include <ccan/endian/endian.h>
#include <ccan/tal/tal.h>
#include <ccan/err/err.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "types.h"
#include "parse.h"
#include "space.h"

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
	le32 ret;

	pull_bytes(f, poff, &ret, sizeof(ret));
	return le32_to_cpu(ret);
}

static u64 pull_u64(struct file *f, off_t *poff)
{
	le64 ret;

	pull_bytes(f, poff, &ret, sizeof(ret));
	return le64_to_cpu(ret);
}

static void pull_hash(struct file *f, off_t *poff, u8 dst[32])
{
	pull_bytes(f, poff, dst, 32);
}

static void read_input(struct space *space, struct file *f, off_t *poff,
		       struct bitcoin_transaction_input *input,
		       bool read_scripts)
{
	pull_hash(f, poff, input->hash);
	input->index = pull_u32(f, poff);
	input->script_length = pull_varint(f, poff);
	if (read_scripts) {
		input->script = space_alloc(space, input->script_length);
		pull_bytes(f, poff, input->script, input->script_length);
	} else {
		input->script = NULL;
		*poff += input->script_length;
	}

	input->sequence_number = pull_u32(f, poff);
}

static void read_output(struct space *space, struct file *f, off_t *poff,
			struct bitcoin_transaction_output *output,
			bool read_scripts)
{
	output->amount = pull_u64(f, poff);
	output->script_length = pull_varint(f, poff);
	if (read_scripts) {
		output->script = space_alloc(space, output->script_length);
		pull_bytes(f, poff, output->script, output->script_length);
	} else {
		output->script = NULL;
		*poff += output->script_length;
	}
}

void read_bitcoin_transaction(struct space *space,
			      struct bitcoin_transaction *trans,
			      struct file *f, off_t *poff,
			      bool read_scripts)
{
	size_t i;
	off_t start = *poff;
	SHA256_CTX sha256;

	trans->version = pull_u32(f, poff);
	trans->input_count = pull_varint(f, poff);
	trans->input = space_alloc_arr(space,
				       struct bitcoin_transaction_input,
				       trans->input_count);
	for (i = 0; i < trans->input_count; i++)
		read_input(space, f, poff, trans->input + i, read_scripts);
	trans->output_count = pull_varint(f, poff);
	trans->output = space_alloc_arr(space,
					struct bitcoin_transaction_output,
					trans->output_count);
	for (i = 0; i < trans->output_count; i++)
               read_output(space, f, poff, trans->output + i, read_scripts);
	trans->lock_time = pull_u32(f, poff);

	/* Bitcoin uses double sha (it's not quite known why...) */
	SHA256_Init(&sha256);
	if (likely(f->mmap)) {
		SHA256_Update(&sha256, f->mmap + start, *poff - start);
	} else {
		u8 *buf = tal_arr(NULL, u8, *poff - start);
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
bool next_block_header_prefix(struct file *f, off_t *off, const u32 marker)
{
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
			  u8 block_md[SHA256_DIGEST_LENGTH],
			  const u32 marker)
{
	struct bitcoin_block *block;
	SHA256_CTX sha256;
	off_t start;

	block = tal(ctx, struct bitcoin_block);
	block->D9B4BEF9 = pull_u32(f, off);
	assert(block->D9B4BEF9 == marker);
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

	return block;
}

void skip_bitcoin_transactions(const struct bitcoin_block *b,
			       off_t block_start,
			       off_t *off)
{
	*off = block_start + 8 + b->len;
}
