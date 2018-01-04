#include "dump.h"
#include <ccan/str/hex/hex.h>
#include <ccan/endian/endian.h>
#include <stdio.h>

void print_hash(const u8 *hash)
{
	char str[hex_str_size(SHA256_DIGEST_LENGTH)];

	hex_encode(hash, SHA256_DIGEST_LENGTH, str, sizeof(str));
	fputs(str, stdout);
}

void print_reversed_hash(const u8 *hash)
{
	u8 reversed[32];
	for(int i=0;i<32;++i) {
		reversed[i]=hash[32-i-1];
	}
	print_hash(reversed);
}


void print_hex(const void *data, size_t len)
{
	char str[len * 2 + 1];

	hex_encode(data, len, str, sizeof(str));
	fputs(str, stdout);
}

static void print_varint(varint_t v)
{
	u8 buf[9], *p = buf;

	if (v < 0xfd) {
		*(p++) = v;
	} else if (v <= 0xffff) {
		(*p++) = 0xfd;
		(*p++) = v;
		(*p++) = v >> 8;
	} else if (v <= 0xffffffff) {
		(*p++) = 0xfe;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
	} else {
		(*p++) = 0xff;
		(*p++) = v;
		(*p++) = v >> 8;
		(*p++) = v >> 16;
		(*p++) = v >> 24;
		(*p++) = v >> 32;
		(*p++) = v >> 40;
		(*p++) = v >> 48;
		(*p++) = v >> 56;
	}
	print_hex(buf, p - buf);
}

static void print_le32(u32 v)
{
	le32 l = cpu_to_le32(v);
	print_hex(&l, sizeof(l));
}

static void print_le64(u64 v)
{
	le64 l = cpu_to_le64(v);
	print_hex(&l, sizeof(l));
}

void dump_tx_input(const struct bitcoin_transaction_input *input)
{
	print_hash(input->hash);
	print_le32(input->index);
	print_varint(input->script_length);
	print_hex(input->script, input->script_length);
	print_le32(input->sequence_number);
}

void dump_tx_output(const struct bitcoin_transaction_output *output)
{
	print_le64(output->amount);
	print_varint(output->script_length);
	print_hex(output->script, output->script_length);
}

void dump_tx(const struct bitcoin_transaction *tx)
{
	varint_t i;

	print_le32(tx->version);
	print_varint(tx->input_count);
	for (i = 0; i < tx->input_count; i++)
		dump_tx_input(&tx->input[i]);
	print_varint(tx->output_count);
	for (i = 0; i < tx->output_count; i++)
		dump_tx_output(&tx->output[i]);
	print_le32(tx->lock_time);
}

void dump_block_header(const struct bitcoin_block *b)
{
	print_le32(b->version);
	print_hash(b->prev_hash);
	print_hash(b->merkle_hash);
	print_le32(b->timestamp);
	print_le32(b->target);
	print_le32(b->nonce);
}
