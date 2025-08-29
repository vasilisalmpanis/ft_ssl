#include <ft_ssl.h>

// Spec: https://datatracker.ietf.org/doc/html/rfc6234
static void sha256_init(struct program_ctx *ctx);
static void sha256_digest(struct program_ctx *ctx, bool stdin);
static void sha256_free(struct program_ctx *ctx);

struct hash_type sha256_type = {
	.name 		= "sha256", 
	.id 		= SHA256,
	.digest_size 	= 32, 
	.init 		= sha256_init, 
	.digest 	= sha256_digest, 
	.free 		= sha256_free
};

struct sha256_data {
	uint64_t bits_len;
	uint8_t *msg;
	size_t total_len;
	uint32_t buffer[8];
	uint8_t digest[32];
};

static uint32_t K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline uint32_t ROTR(uint32_t x, uint32_t n)
{
	return (x >> n) | (x << (32 - n));
}

static inline uint32_t SHR(uint32_t x, uint32_t n)
{
	return x >> n;
}

static inline uint32_t CH(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (~x & z);
}

static inline uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t BSIG0(uint32_t x)
{
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static inline uint32_t BSIG1(uint32_t x)
{
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static inline uint32_t SSIG0(uint32_t x)
{
	return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

static inline uint32_t SSIG1(uint32_t x)
{
	return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

static void sha256_init(struct program_ctx *ctx)
{
	struct sha256_data *data = malloc(sizeof(struct sha256_data));
	if (data == NULL) error("Fatal: Out of memory");

	memset(data, 0, sizeof(struct sha256_data));
	ctx->data = data;

	size_t new_len = ctx->user_input_len + 1;
	while (new_len % 64 != 56) new_len++;
	size_t total_len = new_len + 8;
	uint8_t *msg = calloc(total_len, 1);
	if (!msg) {
		free(ctx->data);
		error("Fatal: Out of memory on calloc %lu %lu %lu %s\n", total_len, new_len, ctx->user_input_len, ctx->user_input);
	}
	memcpy(msg, ctx->user_input, ctx->user_input_len);
	msg[ctx->user_input_len] = 0x80;
	uint64_t bits_length = (uint64_t)ctx->user_input_len * 8;
	for (int i = 0; i < 8; i++) {
		msg[new_len + 7 - i] = (bits_length >> (i * 8)) & 0xff;
	}
	data->total_len = total_len;
	data->bits_len = bits_length;
	data->msg = msg;
}

// Helpers for big-endian load/store
static inline uint32_t load_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) |
		((uint32_t)p[1] << 16) |
		((uint32_t)p[2] <<  8) |
		((uint32_t)p[3] <<  0);
}
static inline void store_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >>  8);
	p[3] = (uint8_t)(v >>  0);
}

static void sha256_digest(struct program_ctx *ctx, bool stdin)
{
	struct sha256_data *data = (struct sha256_data *)ctx->data;

	// Initial hash values (per FIPS 180-4 / RFC 6234)
	uint32_t h0 = 0x6a09e667U;
	uint32_t h1 = 0xbb67ae85U;
	uint32_t h2 = 0x3c6ef372U;
	uint32_t h3 = 0xa54ff53aU;
	uint32_t h4 = 0x510e527fU;
	uint32_t h5 = 0x9b05688cU;
	uint32_t h6 = 0x1f83d9abU;
	uint32_t h7 = 0x5be0cd19U;

	const uint8_t *msg = data->msg;
	size_t total_len = data->total_len;

	// Process 512-bit (64-byte) chunks
	for (size_t off = 0; off < total_len; off += 64) {
		uint32_t W[64];

		//    First 16 words are the block interpreted as big-endian 32-bit ints.
		for (int t = 0; t < 16; ++t) {
			W[t] = load_be32(msg + off + (t * 4));
		}
		//    Extend to 64 words with the σ0/σ1 functions
		for (int t = 16; t < 64; ++t) {
			W[t] = SSIG1(W[t-2]) + W[t-7] + SSIG0(W[t-15]) + W[t-16];
		}

		uint32_t a = h0;
		uint32_t b = h1;
		uint32_t c = h2;
		uint32_t d = h3;
		uint32_t e = h4;
		uint32_t f = h5;
		uint32_t g = h6;
		uint32_t h = h7;

		// Main compression loop
		for (int t = 0; t < 64; ++t) {
			uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + (uint32_t)K[t] + W[t];
			uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		// Add the compressed chunk to the current hash value
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	store_be32(&data->digest[ 0], h0);
	store_be32(&data->digest[ 4], h1);
	store_be32(&data->digest[ 8], h2);
	store_be32(&data->digest[12], h3);
	store_be32(&data->digest[16], h4);
	store_be32(&data->digest[20], h5);
	store_be32(&data->digest[24], h6);
	store_be32(&data->digest[28], h7);

	print_digest(ctx, "MD5", data->digest, stdin);
}

static void sha256_free(struct program_ctx *ctx)
{
	if (ctx->data) {
		struct sha256_data *data = (struct sha256_data*)ctx->data;
		if (data->msg)
			free(data->msg);
		free(ctx->data);
	}
}
