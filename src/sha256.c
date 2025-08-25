#include <ft_ssl.h>
#include <signal.h>


static void sha256_init(struct program_ctx *ctx);
static void sha256_digest(struct program_ctx *ctx);
static void sha256_free(struct program_ctx *ctx);

struct hash_type sha256_type = {
	.name 		= "sha256", 
	.id 		= MD5, 
	.digest_size 	= 32, 
	.init 		= sha256_init, 
	.digest 	= sha256_digest, 
	.free 		= sha256_free
};

struct sha256_data {
	uint64_t bits_len;
	uint8_t *msg;
	size_t total_len;
	uint32_t buffer[4];
	uint8_t digest[16];
};

__attribute__((unused))
static int K[] = {
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

__attribute__((unused))
static inline uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__attribute__((unused))
static inline uint32_t SHR(uint32_t x, uint32_t n) {
    return x >> n;
}

__attribute__((unused))
static inline uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__attribute__((unused))
static inline uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__attribute__((unused))
static inline uint32_t BSIG0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

__attribute__((unused))
static inline uint32_t BSIG1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

__attribute__((unused))
static inline uint32_t SSIG0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

__attribute__((unused))
static inline uint32_t SSIG1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

__attribute__((unused))
static void print_sha256_digest(struct program_ctx* ctx, uint8_t *digest)
{
	if (ctx->user_input)
		printf("SHA2-256(%s)= ", ctx->user_input);
	else
		printf("SHA2-256(stdin)= ");
	for(int i = 0; i < 16; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
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
	memcpy(msg + new_len, &bits_length, 8);
	data->total_len = total_len;
	data->bits_len = bits_length;
	data->msg = msg;
}

static void sha256_digest(struct program_ctx *ctx){
	(void)ctx;
}

static void sha256_free(struct program_ctx *ctx)
{
	(void)ctx;
}
