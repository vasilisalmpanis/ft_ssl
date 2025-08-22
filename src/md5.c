#include <ft_ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void md5_init(struct program_ctx *ctx);
static void md5_update(struct program_ctx *ctx, uint8_t *input_buffer, size_t input_len);
static void md5_step(uint32_t *buffer, uint32_t *input);
static void md5_finalize(struct program_ctx *ctx);
static void md5_free(struct program_ctx *ctx);

struct hash_type md5_type = {"md5", MD5, 16, md5_init, md5_update, md5_finalize, md5_free};

struct md5_data {
	uint64_t size;
	uint32_t buffer[4];
	uint8_t input[64];
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

/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
static uint8_t PADDING[] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

static void print_md5_digest(uint8_t *digest)
{
	printf("MD5(stdin)= ");
	for(int i = 0; i < 16; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");
}

static void md5_init(struct program_ctx *ctx)
{
	ctx->digest = (uint8_t *)malloc(md5_type.digest_size);
	if (ctx->digest == NULL) error("Fatal: Out of memory");
	memset(ctx->digest, 0, md5_type.digest_size);
	struct md5_data *data = malloc(sizeof(struct md5_data));
	if (data == NULL) {
		free(ctx->digest);
		error("Fatal: Out of memory");
	}
	memset(data, 0, sizeof(struct md5_data));
	data->buffer[0] = A;
	data->buffer[1] = B;
	data->buffer[2] = C;
	data->buffer[3] = D;
	ctx->data = data;
}

static void md5_update(struct program_ctx *ctx, uint8_t *input_buffer, size_t input_len){
	struct md5_data *data = (struct md5_data *)ctx->data;
	uint32_t input[16];
	unsigned int offset = data->size % 64;
	data->size += (uint64_t)input_len;

	// Copy each byte in input_buffer into the next space in our context input
	for(unsigned int i = 0; i < input_len; ++i){
		data->input[offset++] = (uint8_t)*(input_buffer + i);

		// If we've filled our context input, copy it into our local array input
		// then reset the offset to 0 and fill in a new buffer.
		// Every time we fill out a chunk, we run it through the algorithm
		// to enable some back and forth between cpu and i/o
		if(offset % 64 == 0){
			for(unsigned int j = 0; j < 16; ++j){
				// Convert to little-endian
				// The local variable `input` our 512-bit chunk separated into 32-bit words
				// we can use in calculations
				input[j] = (uint32_t)(data->input[(j * 4) + 3]) << 24 |
					(uint32_t)(data->input[(j * 4) + 2]) << 16 |
					(uint32_t)(data->input[(j * 4) + 1]) <<  8 |
					(uint32_t)(data->input[(j * 4)]);
			}
			md5_step(data->buffer, input);
			offset = 0;
		}
	}
}

uint32_t rotateLeft(uint32_t x, uint32_t n){
	return (x << n) | (x >> (32 - n));
}

static void md5_step(uint32_t *buffer, uint32_t *input)
{
	uint32_t AA = buffer[0];
	uint32_t BB = buffer[1];
	uint32_t CC = buffer[2];
	uint32_t DD = buffer[3];

	uint32_t E;

	unsigned int j;

	for(unsigned int i = 0; i < 64; ++i){
		switch(i / 16){
			case 0:
				E = F(BB, CC, DD);
				j = i;
				break;
			case 1:
				E = G(BB, CC, DD);
				j = ((i * 5) + 1) % 16;
				break;
			case 2:
				E = H(BB, CC, DD);
				j = ((i * 3) + 5) % 16;
				break;
			default:
				E = I(BB, CC, DD);
				j = (i * 7) % 16;
				break;
		}

		uint32_t temp = DD;
		DD = CC;
		CC = BB;
		BB = BB + rotateLeft(AA + E + K[i] + input[j], S[i]);
		AA = temp;
	}

	buffer[0] += AA;
	buffer[1] += BB;
	buffer[2] += CC;
	buffer[3] += DD;
}

static void md5_finalize(struct program_ctx *ctx)
{
	uint32_t input[16];
	struct md5_data *data = (struct md5_data *)ctx->data;
	unsigned int offset = data->size % 64;
	unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

	// Add padding directly to the input buffer
	if (padding_length > 0) {
		memcpy(data->input + offset, PADDING, padding_length);
	}

	// Process all 16 words from the input buffer
	for(unsigned int j = 0; j < 16; ++j){
		input[j] = (uint32_t)(data->input[(j * 4) + 3]) << 24 |
			(uint32_t)(data->input[(j * 4) + 2]) << 16 |
			(uint32_t)(data->input[(j * 4) + 1]) <<  8 |
			(uint32_t)(data->input[(j * 4)]);
	}

	// Set the length in the last two words (little-endian)
	input[14] = (uint32_t)(data->size * 8);
	input[15] = (uint32_t)((data->size * 8) >> 32);

	md5_step(data->buffer, input);

	// Move the result into digest (convert from little-endian)
	for(unsigned int i = 0; i < 4; ++i){
		data->digest[(i * 4) + 0] = (uint8_t)((data->buffer[i] & 0x000000FF));
		data->digest[(i * 4) + 1] = (uint8_t)((data->buffer[i] & 0x0000FF00) >>  8);
		data->digest[(i * 4) + 2] = (uint8_t)((data->buffer[i] & 0x00FF0000) >> 16);
		data->digest[(i * 4) + 3] = (uint8_t)((data->buffer[i] & 0xFF000000) >> 24);
	}

	// Copy the final digest to the context
	memcpy(ctx->digest, data->digest, md5_type.digest_size);
	print_md5_digest(ctx->digest);
}

static void md5_free(struct program_ctx *ctx)
{
	if (ctx->digest)
		free(ctx->digest);
	if (ctx->data)
		free(ctx->data);
}
