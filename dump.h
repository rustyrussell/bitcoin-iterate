#ifndef BITCOIN_ITERATE_DUMP_H
#define BITCOIN_ITERATE_DUMP_H
#include "types.h"
#include "io.h"

void print_hex(const void *data, size_t len);
void print_hash(const struct sha256 *hash);
void print_reversed_hash(const struct sha256 *hash);

void dump_block_header(const struct bitcoin_block *b);
void dump_tx(const struct bitcoin_transaction *tx);
void dump_tx_input(const struct bitcoin_transaction_input *input);
void dump_tx_output(const struct bitcoin_transaction_output *output);

/* Helper */
struct sha256 reverse_hash(const struct sha256 *hash);

#endif /* BITCOIN_ITERATE_DUMP_H */
