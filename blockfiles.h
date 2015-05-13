#include <ccan/tal/tal.h>

/* Return a tal_array of filenames. */
char **block_filenames(tal_t *ctx, const char *base);
