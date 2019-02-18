#include <ccan/tal/tal.h>

enum networks {
    MAIN,
    TESTNET3,
    REGTEST
};

/* Return a tal_array of filenames. */
char **block_filenames(tal_t *ctx, const char *base, unsigned int network);