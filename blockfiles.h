#include <ccan/tal/tal.h>

#define XOR_KEY_SIZE 8

enum networks {
    MAIN,
    TESTNET3,
    REGTEST,
    SIGNET
};

/* Return a tal_array of filenames, may fill in *xorkey */
char **block_filenames(tal_t *ctx, const char *base, enum networks network,
		       u8 **xorkey);
