#include <ft_ssl.h>


static void md5_init(struct program_ctx *ctx);
static void md5_digest(struct program_ctx *ctx);
static void md5_free(struct program_ctx *ctx);

struct hash_type md5_type = {"md5", MD5, 16, md5_init, md5_digest, md5_free};

struct md5_data {
	uint64_t bits_len;
	uint8_t *msg;
	size_t total_len;
	uint32_t buffer[4];
	uint8_t digest[16];
};

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

static uint32_t S[] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t K[] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define F(X, Y, Z) ((X & Y) | ((~X) & Z))
#define G(X, Y, Z) ((X & Z) | ((~X) & Y))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | (~Z)))

uint32_t rotateLeft(uint32_t x, uint32_t n){
	return (x << n) | (x >> (32 - n));
}

static void print_md5_digest(struct program_ctx* ctx, uint8_t *digest)
{
	if (ctx->user_input)
		printf("MD5(%s)= ", ctx->user_input);
	else
		printf("MD5(stdin)= ");
	for(int i = 0; i < 16; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}

/*
 * MD% steps
 * 1. Input Padding
 * 2. Length Appending
 * 3. Buffer Initialization
 * 4. Message Processing
 * 5. Output
 */
static void md5_init(struct program_ctx *ctx)
{
	struct md5_data *data = malloc(sizeof(struct md5_data));
	if (data == NULL) error("Fatal: Out of memory");

	memset(data, 0, sizeof(struct md5_data));
	data->buffer[0] = A;
	data->buffer[1] = B;
	data->buffer[2] = C;
	data->buffer[3] = D;
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

static void md5_digest(struct program_ctx *ctx){
	struct md5_data *data = ctx->data;
	for (size_t offset = 0; offset < data->total_len; offset += 64) {
		// Break chunk into sixteen 32-bit words M[j] in little-endian
		uint32_t M[16];
		for (int j = 0; j < 16; j++) {
			// Read 4 bytes little-endian into uint32_t
			uint32_t m =
				(uint32_t)data->msg[offset + j*4 + 0]        |
				((uint32_t)data->msg[offset + j*4 + 1] << 8) |
				((uint32_t)data->msg[offset + j*4 + 2] << 16)|
				((uint32_t)data->msg[offset + j*4 + 3] << 24);
			M[j] = m;
		}

		uint32_t a = data->buffer[0];
		uint32_t b = data->buffer[1];
		uint32_t c = data->buffer[2];
		uint32_t d = data->buffer[3];

		for (uint32_t i = 0; i < 64; i++) {
			uint32_t F, g;

			if (i <= 15) {
				F = (b & c) | ((~b) & d);
				g = i;
			} else if (i <= 31) {
				F = (d & b) | ((~d) & c);
				g = (5*i + 1) & 0x0F;
			} else if (i <= 47) {
				F = b ^ c ^ d;
				g = (3*i + 5) & 0x0F;
			} else {
				F = c ^ (b | (~d));
				g = (7*i) & 0x0F;
			}

			uint32_t tmp = d;
			d = c;
			c = b;

			uint32_t to_rot = a + F + K[i] + M[g];
			b = b + rotateLeft(to_rot, S[i]);
			a = tmp;
		}

		data->buffer[0] += a;
		data->buffer[1] += b;
		data->buffer[2] += c;
		data->buffer[3] += d;
	}

	uint8_t output[16];
	memcpy(output + 0,  &data->buffer[0], 4);
	memcpy(output + 4,  &data->buffer[1], 4);
	memcpy(output + 8,  &data->buffer[2], 4);
	memcpy(output + 12, &data->buffer[3], 4);
	print_md5_digest(ctx, output);
}

static void md5_free(struct program_ctx *ctx)
{
	if (ctx->data) {
		struct md5_data *data = (struct md5_data*)ctx->data;
		if (data->msg)
			free(data->msg);
		free(ctx->data);
	}
}
