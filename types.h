#ifndef BITCOIN_PARSE_TYPES_H
#define BITCOIN_PARSE_TYPES_H
#include <stdbool.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/short_types/short_types.h>
#include <string.h>

/* We unpack varints for our in-memory representation */
#define varint_t u64

/* These are little endian on disk. */
struct bitcoin_block {
	u32 D9B4BEF9;
	u32 len;
	u32 version;
	struct sha256 prev_hash;
	struct sha256 merkle_hash;
	u32 timestamp;
	u32 target;
	u32 nonce;
	varint_t transaction_count;
};

struct bitcoin_transaction {
	u32 version;
	varint_t input_count;
	struct bitcoin_transaction_input *input;
	varint_t output_count;
	struct bitcoin_transaction_output *output;
	u32 lock_time;

	/* We calculate these as we read in transaction: */
	struct sha256 sha256;
	/* Length of non-segwit part */
	u32 non_swlen;
	/* Total length, including segwit part */
	u32 total_len;
};

struct bitcoin_transaction_output {
	u64 amount;
	varint_t script_length;
	u8 *script;
};

struct bitcoin_transaction_input {
	struct sha256 hash;
	u32 index; /* output number referred to by above */
	varint_t script_length;
	u8 *script;
	varint_t num_witness;
	u8 **witness;
	u32 sequence_number;
};

#define OP_PUSHDATA1	0x4C
#define OP_PUSHDATA2	0x4D
#define OP_PUSHDATA4	0x4E
#define OP_NOP		0x61
#define OP_RETURN	0x6A
#define OP_DUP		0x76
#define OP_EQUALVERIFY	0x88
#define OP_CHECKSIG	0xAC
#define OP_HASH160	0xA9

static inline bool sha256_eq(const struct sha256 *a, const struct sha256 *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

#endif /* BITCOIN_PARSE_TYPES_H */
