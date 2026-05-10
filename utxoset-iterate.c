/* GPLv2 or later, see LICENSE */
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/tal.h>
#include <ccan/short_types/short_types.h>
#include <ccan/opt/opt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <openssl/bn.h>
#include "types.h"
#include "io.h"
#include "dump.h"

static bool verbose = false;

static void pull_bytes(struct file *f, off_t *poff, void *dst, size_t num)
{
	if ((off_t)(*poff + num) > f->len)
		errx(1, "Unexpected end of file at offset %llu (need %zu bytes)",
		     (unsigned long long)*poff, num);
	if (f->mmap)
		memcpy(dst, (u8 *)f->mmap + *poff, num);
	else
		file_read(f, *poff, num, dst);
	if (verbose) {
		char hex[hex_str_size(num)];
		hex_encode(dst, num, hex, sizeof(hex));
		fprintf(stderr, "  @%llu: %s\n", (unsigned long long)*poff, hex);
	}
	*poff += num;
}

static u32 pull_u32le(struct file *f, off_t *poff)
{
	u8 b[4];
	pull_bytes(f, poff, b, sizeof(b));
	return (u32)b[0] | ((u32)b[1] << 8) | ((u32)b[2] << 16) | ((u32)b[3] << 24);
}

static u64 pull_u64le(struct file *f, off_t *poff)
{
	u8 b[8];
	pull_bytes(f, poff, b, sizeof(b));
	return (u64)b[0] | ((u64)b[1] << 8) | ((u64)b[2] << 16) | ((u64)b[3] << 24)
	     | ((u64)b[4] << 32) | ((u64)b[5] << 40) | ((u64)b[6] << 48) | ((u64)b[7] << 56);
}

/* Bitcoin Core's MSB base-128 VARINT (used for coin code and compressed amount) */
static u64 pull_core_varint(struct file *f, off_t *poff)
{
	u64 n = 0;
	for (;;) {
		u8 byte;
		pull_bytes(f, poff, &byte, 1);
		n = (n << 7) | (byte & 0x7F);
		if (byte & 0x80)
			n++;
		else
			break;
	}
	return n;
}

/* Bitcoin protocol COMPACTSIZE varint (used for script nSize) */
static u64 pull_compactsize(struct file *f, off_t *poff)
{
	u8 first;
	pull_bytes(f, poff, &first, 1);
	if (first < 0xFD)
		return first;
	if (first == 0xFD) {
		u8 b[2];
		pull_bytes(f, poff, b, 2);
		return (u64)b[0] | ((u64)b[1] << 8);
	}
	if (first == 0xFE) {
		u8 b[4];
		pull_bytes(f, poff, b, 4);
		return (u64)b[0] | ((u64)b[1] << 8) | ((u64)b[2] << 16) | ((u64)b[3] << 24);
	}
	/* 0xFF */
	return pull_u64le(f, poff);
}

/* Bitcoin Core amount decompression */
static u64 decompress_amount(u64 x)
{
	if (x == 0)
		return 0;
	x--;
	int e = x % 10;
	x /= 10;
	u64 n;
	if (e < 9) {
		int d = (x % 9) + 1;
		x /= 9;
		n = x * 10 + d;
	} else {
		n = x + 1;
	}
	while (e--)
		n *= 10;
	return n;
}

/* Decompress secp256k1 point using BIGNUM arithmetic */
static void decompress_pubkey(const u8 compressed[33], u8 uncompressed[65])
{
	/* secp256k1: y^2 = x^3 + 7 (mod p) */
	static const u8 p_bytes[32] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F
	};

	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x = BN_new(), *y = BN_new(), *p = BN_new();
	BIGNUM *tmp = BN_new(), *exp = BN_new();

	BN_bin2bn(compressed + 1, 32, x);
	BN_bin2bn(p_bytes, 32, p);

	/* y^2 = x^3 + 7 mod p */
	BN_mod_sqr(tmp, x, p, ctx);
	BN_mod_mul(tmp, tmp, x, p, ctx);
	BN_add_word(tmp, 7);
	BN_mod(tmp, tmp, p, ctx);

	/* Since p ≡ 3 (mod 4): y = tmp^((p+1)/4) mod p */
	BN_copy(exp, p);
	BN_add_word(exp, 1);
	BN_rshift(exp, exp, 2);
	BN_mod_exp(y, tmp, exp, p, ctx);

	/* Choose correct y parity */
	if (BN_is_odd(y) != (compressed[0] == 0x03))
		BN_sub(y, p, y);

	uncompressed[0] = 0x04;
	BN_bn2binpad(x, uncompressed + 1, 32);
	BN_bn2binpad(y, uncompressed + 33, 32);

	BN_free(x); BN_free(y); BN_free(p); BN_free(tmp); BN_free(exp);
	BN_CTX_free(ctx);
}

/* Read and decompress script from snapshot; sets *script_len */
static u8 *pull_script(const tal_t *ctx, struct file *f, off_t *poff,
		       u32 *script_len)
{
	u64 nsize = pull_core_varint(f, poff);
	u8 *script;

	switch (nsize) {
	case 0x00: {
		/* P2PKH */
		u8 hash[20];
		pull_bytes(f, poff, hash, 20);
		*script_len = 25;
		script = tal_arr(ctx, u8, 25);
		script[0] = 0x76; /* OP_DUP */
		script[1] = 0xA9; /* OP_HASH160 */
		script[2] = 20;
		memcpy(script + 3, hash, 20);
		script[23] = 0x88; /* OP_EQUALVERIFY */
		script[24] = 0xAC; /* OP_CHECKSIG */
		return script;
	}
	case 0x01: {
		/* P2SH */
		u8 hash[20];
		pull_bytes(f, poff, hash, 20);
		*script_len = 23;
		script = tal_arr(ctx, u8, 23);
		script[0] = 0xA9; /* OP_HASH160 */
		script[1] = 20;
		memcpy(script + 2, hash, 20);
		script[22] = 0x87; /* OP_EQUAL */
		return script;
	}
	case 0x02:
	case 0x03: {
		/* P2PK (compressed pubkey) */
		u8 key[32];
		pull_bytes(f, poff, key, 32);
		*script_len = 35;
		script = tal_arr(ctx, u8, 35);
		script[0] = 33;
		script[1] = nsize; /* 0x02 or 0x03 */
		memcpy(script + 2, key, 32);
		script[34] = 0xAC; /* OP_CHECKSIG */
		return script;
	}
	case 0x04:
	case 0x05: {
		/* P2PK (uncompressed pubkey) */
		u8 comp[33], uncomp[65];
		comp[0] = (nsize == 0x04) ? 0x02 : 0x03;
		pull_bytes(f, poff, comp + 1, 32);
		decompress_pubkey(comp, uncomp);
		*script_len = 67;
		script = tal_arr(ctx, u8, 67);
		script[0] = 65;
		memcpy(script + 1, uncomp, 65);
		script[66] = 0xAC; /* OP_CHECKSIG */
		return script;
	}
	default: {
		/* Raw script; length = nsize - 6 */
		if (nsize < 6)
			errx(1, "Invalid script nsize %"PRIu64, nsize);
		u32 len = nsize - 6;
		*script_len = len;
		script = tal_arr(ctx, u8, len ? len : 1);
		pull_bytes(f, poff, script, len);
		return script;
	}
	}
}

struct utxo_entry {
	u8 txid[32];
	u32 vout;
	u64 amount;
	u32 height;
	bool coinbase;
	u32 script_len;
	u8 *script;
};

static void print_format(const char *format, const struct utxo_entry *u)
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
			case 'N':
				printf("%u", u->height);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 't':
			switch (c[2]) {
			case 'h':
				print_reversed_hash(u->txid);
				break;
			case 'C':
				printf("%u", u->coinbase);
				break;
			default:
				goto bad_fmt;
			}
			break;
		case 'o':
			switch (c[2]) {
			case 'N':
				printf("%u", u->vout);
				break;
			case 'a':
				printf("%"PRIu64, u->amount);
				break;
			case 'l':
				printf("%u", u->script_len);
				break;
			case 's':
				print_hex(u->script, u->script_len);
				break;
			default:
				goto bad_fmt;
			}
			break;
		default:
			goto bad_fmt;
		}
		c += 2;
	}
	fputc('\n', stdout);
	return;

bad_fmt:
	errx(1, "Bad format %.3s", c);
}

int main(int argc, char *argv[])
{
	void *tal_ctx = tal(NULL, char);
	char *outputfmt = NULL;
	bool quiet = false;

	err_set_progname(argv[0]);
	opt_register_noarg("-h|--help", opt_usage_and_exit,
		"<dumputxsosetfile>\n"
		"Reads a Bitcoin Core dumptxoutset file and iterates UTXOs.\n"
		"Valid output format specifiers:\n"
		"  %bN: block height at which UTXO was created\n"
		"  %th: transaction id (big-endian hex)\n"
		"  %tC: 1 if coinbase output, 0 otherwise\n"
		"  %oN: output (vout) index\n"
		"  %oa: output amount in satoshis\n"
		"  %ol: output script length\n"
		"  %os: output script as hex\n",
		"Display help message");
	opt_register_arg("--output", opt_set_charp, NULL, &outputfmt,
		"Format to print for each UTXO");
	opt_register_noarg("--quiet|-q", opt_set_bool, &quiet,
		"Don't output progress information");
	opt_register_noarg("--verbose|-v", opt_set_bool, &verbose,
		"Print every byte read.");
	opt_parse(&argc, argv, opt_log_stderr_exit);

	if (argc != 2)
		opt_usage_and_exit(NULL);

	struct file f;
	file_open(&f, argv[1], 0, O_RDONLY);

	off_t off = 0;

	/* v28+ snapshot header:
	 * 5 bytes: magic "utxo\xff"
	 * 2 bytes: uint16 LE version
	 * 4 bytes: uint32 network magic
	 * 32 bytes: base block hash
	 * 8 bytes: uint64 LE coins count
	 */
	static const u8 expected_magic[5] = {'u','t','x','o', 0xff};
	u8 magic[5];
	pull_bytes(&f, &off, magic, 5);
	if (memcmp(magic, expected_magic, 5) != 0)
		errx(1, "Not a Bitcoin Core snapshot file (bad magic)");

	u8 vbytes[2];
	pull_bytes(&f, &off, vbytes, 2);
	u16 version = (u16)vbytes[0] | ((u16)vbytes[1] << 8);
	u32 network_magic = pull_u32le(&f, &off);

	u8 base_hash[32];
	pull_bytes(&f, &off, base_hash, 32);
	u64 coins_count = pull_u64le(&f, &off);

	if (!quiet) {
		fprintf(stderr, "utxoset-iterate: snapshot v%u network 0x%08x base block ",
			version, network_magic);
		for (int i = 31; i >= 0; i--)
			fprintf(stderr, "%02x", base_hash[i]);
		fprintf(stderr, " (%"PRIu64" coins)\n", coins_count);
	}

	/* v28+ format groups outputs by TXID:
	 *   txid (32 bytes)
	 *   output_count (CompactSize)
	 *   for each output:
	 *     vout (CompactSize)
	 *     coin_code (VarInt: height*2 + coinbase)
	 *     amount (VarInt, compressed)
	 *     script (VarInt nsize + data)
	 */
	u64 i = 0;
	while (i < coins_count) {
		u8 txid[32];
		pull_bytes(&f, &off, txid, 32);

		u64 out_count = pull_compactsize(&f, &off);

		for (u64 j = 0; j < out_count; j++, i++) {
			struct utxo_entry u;
			memcpy(u.txid, txid, 32);
			u.vout = (u32)pull_compactsize(&f, &off);

			u64 code = pull_core_varint(&f, &off);
			u.height = code >> 1;
			u.coinbase = code & 1;

			u.amount = decompress_amount(pull_core_varint(&f, &off));
			u.script = pull_script(tal_ctx, &f, &off, &u.script_len);

			if (outputfmt)
				print_format(outputfmt, &u);

			tal_free(u.script);
		}
	}

	file_close(&f);
	tal_free(tal_ctx);
	return 0;
}
