#ifndef BITCOIN_PARSE_PARSE_H
#define BITCOIN_PARSE_PARSE_H
#include "types.h"
#include "io.h"

struct space;

/* Step 1: Fast forward *off to head of next block, or false if not found. */
bool next_block_header_prefix(struct file *f, off_t *off, const u32 marker);

/* Step 2: Now, read in the block header, and calculate double-SHA*/
struct bitcoin_block *read_bitcoin_block_header(tal_t *ctx,
						struct file *f, off_t *off,
						u8 block_md[SHA256_DIGEST_LENGTH],
						const u32 marker);

/* Step 3: Either skip all the transactions, or... */
void skip_bitcoin_transactions(const struct bitcoin_block *b,
			       off_t block_start, off_t *off);

/* ... read them in (call this repeatedly). Allocates off ctx. */
void read_bitcoin_transaction(struct space *space,
			      struct bitcoin_transaction *t,
			      struct file *f, off_t *off,
			      bool read_scripts);
#endif /* BITCOIN_PARSE_PARSE_H */
