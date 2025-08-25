#include <ft_ssl.h>


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
	(void)ctx;
}

static void sha256_digest(struct program_ctx *ctx){
	(void)ctx;
}

static void sha256_free(struct program_ctx *ctx)
{
	(void)ctx;
}
